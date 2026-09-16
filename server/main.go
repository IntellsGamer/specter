package main

// Specter v3 server: X25519 forward secrecy + HKDF session keys + AEAD cells.
// Env: SPECTER_PSK (64 hex, required, long-term salt/auth only).
//      SPECTER_LISTEN (default ":43117", TCP+UDP). SPECTER_TRANSPORT=tcp -> TCP only.
// NOT audited crypto.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	version   = 0x03
	maxConns  = 1024
	dialTO    = 10 * time.Second
	nonceTTL  = 10 * time.Minute
	udpIdle   = 120 * time.Second
	udpGap    = 500 * time.Millisecond

	udpMaxPayload = 1200
)

// Record size classes (totals on the wire). TCP records carry a 2-byte
// length prefix; UDP sizes come from datagram boundaries.
var tcpClasses = []int{320, 576, 1024, 1420}
var udpClasses = []int{576, 1024, 1280}

func pickClass(classes []int) int {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return classes[len(classes)-1]
	}
	return classes[int(b[0])%len(classes)]
}

func validClass(classes []int, total int) bool {
	for _, c := range classes {
		if c == total {
			return true
		}
	}
	return false
}

var psk = mustPSK()

func mustPSK() []byte {
	b, err := hex.DecodeString(os.Getenv("SPECTER_PSK"))
	if err != nil || len(b) != 32 {
		log.Fatal("SPECTER_PSK must be 64 hex chars")
	}
	return b
}

func listenAddr() string {
	if v := os.Getenv("SPECTER_LISTEN"); v != "" {
		return v
	}
	return "0.0.0.0:43117"
}

// fsKey derives the per-connection AEAD key. PSK is salt/auth only.
func fsKey(shared []byte) []byte {
	r := hkdf.New(func() hash.Hash { return sha256.New() }, shared, psk, []byte("specter-v3"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(err)
	}
	return out
}

// hsKey protects the UDP hello only (server eph pubkey not yet known).
func hsKey(hsNonce []byte) []byte {
	h := sha256.New()
	h.Write(psk)
	h.Write([]byte("specter-v3-hs"))
	h.Write(hsNonce)
	return h.Sum(nil)
}

func genEphemeral() (priv, pub []byte) {
	priv = make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		panic(err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return priv, pub
}

// ---------- replay cache ----------

var nonceCache = struct {
	sync.Mutex
	m map[string]time.Time
}{m: map[string]time.Time{}}

// nonceSeen reports true if seen (caller must still handle UDP hello resend).
func nonceSeen(nonce []byte) bool {
	k := string(nonce)
	now := time.Now()
	nonceCache.Lock()
	defer nonceCache.Unlock()
	if exp, ok := nonceCache.m[k]; ok && now.Before(exp) {
		return true
	}
	nonceCache.m[k] = now.Add(nonceTTL)
	if len(nonceCache.m) > 200000 {
		for kk, exp := range nonceCache.m {
			if now.After(exp) {
				delete(nonceCache.m, kk)
			}
		}
	}
	return false
}

func nonceSweeper() {
	for range time.Tick(time.Minute) {
		now := time.Now()
		nonceCache.Lock()
		for k, exp := range nonceCache.m {
			if now.After(exp) {
				delete(nonceCache.m, k)
			}
		}
		nonceCache.Unlock()
	}
}

// ---------- TCP records (variable size class + 2B length prefix) ----------

// sealRecord encrypts up to budget-2 bytes into a total-sized record:
// len u16 (total-2) || rnonce(12) || AEAD(pt=[dlen u16][data][pad]).
func sealRecord(sk, data []byte, total int) []byte {
	budget := total - 2 - 12 - 16
	if len(data) > budget-2 {
		data = data[:budget-2]
	}
	pt := make([]byte, budget)
	binary.BigEndian.PutUint16(pt[:2], uint16(len(data)))
	copy(pt[2:], data)
	if _, err := rand.Read(pt[2+len(data):]); err != nil {
		panic(err)
	}
	a, _ := chacha20poly1305.New(sk)
	rnonce := make([]byte, 12)
	if _, err := rand.Read(rnonce); err != nil {
		panic(err)
	}
	out := make([]byte, 0, total)
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(total-2))
	out = append(out, hdr[:]...)
	out = append(out, rnonce...)
	out = append(out, a.Seal(nil, rnonce, pt, nil)...)
	return out
}

// openRecordBody decrypts a record body (nonce+AEAD) of known total.
func openRecordBody(sk, body []byte, total int) ([]byte, error) {
	budget := total - 2 - 12 - 16
	if len(body) != total-2 || budget < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	a, _ := chacha20poly1305.New(sk)
	pt, err := a.Open(nil, body[:12], body[12:], nil)
	if err != nil {
		return nil, err
	}
	ln := int(binary.BigEndian.Uint16(pt[:2]))
	if ln < 0 || 2+ln > len(pt) {
		return nil, io.ErrUnexpectedEOF
	}
	return pt[2 : 2+ln], nil
}

// readRecord reads one length-prefixed record, enforcing size classes.
func readRecord(r io.Reader, sk []byte) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	total := int(binary.BigEndian.Uint16(hdr[:])) + 2
	if !validClass(tcpClasses, total) {
		return nil, io.ErrUnexpectedEOF
	}
	body := make([]byte, total-2)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return openRecordBody(sk, body, total)
}

func parseAddr(buf []byte) (host string, rest []byte, ok bool) {
	if len(buf) < 1 {
		return "", nil, false
	}
	switch buf[0] {
	case 0x01:
		if len(buf) < 5 {
			return "", nil, false
		}
		return net.IP(buf[1:5]).String(), buf[5:], true
	case 0x03:
		if len(buf) < 2 || len(buf) < 2+int(buf[1]) {
			return "", nil, false
		}
		return string(buf[2 : 2+int(buf[1])]), buf[2+int(buf[1]):], true
	case 0x04:
		if len(buf) < 17 {
			return "", nil, false
		}
		return net.IP(buf[1:17]).String(), buf[17:], true
	}
	return "", nil, false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// checkHandshake verifies ver + tag over ver||magic||nonce||ephC.
func checkHandshake(hs []byte) (nonce, ephC []byte, ok bool) {
	if len(hs) != 69 || hs[0] != version {
		return nil, nil, false
	}
	m := hmac.New(sha256.New, psk)
	m.Write(hs[:53])
	if !hmac.Equal(m.Sum(nil)[:16], hs[53:69]) {
		return nil, nil, false
	}
	return append([]byte(nil), hs[5:21]...), append([]byte(nil), hs[21:53]...), true
}

func serverReply(ephS, ephC, nonce []byte) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte{version})
	m.Write(ephS)
	m.Write(ephC)
	m.Write(nonce)
	out := make([]byte, 0, 49)
	out = append(out, version)
	out = append(out, ephS...)
	out = append(out, m.Sum(nil)[:16]...)
	return out
}

func handleTCP(c net.Conn, sem chan struct{}) {
	defer c.Close()
	defer func() { <-sem }()
	hs := make([]byte, 69)
	if _, err := io.ReadFull(c, hs); err != nil {
		return
	}
	nonce, ephC, ok := checkHandshake(hs)
	if !ok || nonceSeen(nonce) {
		return
	}
	ephSPriv, ephSPub := genEphemeral()
	shared, err := curve25519.X25519(ephSPriv, ephC)
	if err != nil {
		return
	}
	sk := fsKey(shared)
	sk0 := hsKey(nonce)
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.Write(serverReply(ephSPub, ephC, nonce)); err != nil {
		return
	}
	// first record carries the target under the hello key (0-RTT: the
	// client sends hs+target together before seeing our reply)
	tgt, err := readRecord(c, sk0)
	if err != nil {
		return
	}
	host, rest, ok := parseAddr(tgt)
	if !ok || len(rest) < 2 {
		return
	}
	target := host + ":" + itoa(int(binary.BigEndian.Uint16(rest[:2])))
	t, err := net.DialTimeout("tcp", target, dialTO)
	if err != nil {
		return
	}
	defer t.Close()
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			d, err := readRecord(c, sk)
			if err != nil {
				return
			}
			t.SetDeadline(time.Now().Add(3 * time.Minute))
			if _, err := t.Write(d); err != nil {
				return
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 1388)
		for {
			t.SetDeadline(time.Now().Add(3 * time.Minute))
			n, err := t.Read(buf)
			if err != nil || n == 0 {
				return
			}
			c.SetDeadline(time.Now().Add(3 * time.Minute))
			off := 0
			for off < n {
				total := pickClass(tcpClasses)
				end := off + total - 2 - 12 - 16 - 2
				if end > n {
					end = n
				}
				if _, err := c.Write(sealRecord(sk, buf[off:end], total)); err != nil {
					return
				}
				off = end
			}
		}
	}()
	<-done
}

// ---------- UDP ----------

type udpSession struct {
	target    net.Conn
	sendSeq   uint32
	expect    uint32
	pending   map[uint32][]byte
	gapSince  time.Time
	last      time.Time
	sk        []byte // FS data key
	sk0       []byte // hello/early key (PSK-derived)
	peerReady bool   // client proved FS key (first sk datagram seen)
	ephS      []byte
	ephC      []byte
	hsNonce   []byte
	sid       []byte
	mu        sync.Mutex
}

var (
	udpMu       sync.Mutex
	udpSessions = map[string]*udpSession{}
)

func udpReaper() {
	for range time.Tick(30 * time.Second) {
		now := time.Now()
		udpMu.Lock()
		for k, s := range udpSessions {
			s.mu.Lock()
			idle := now.Sub(s.last) > udpIdle
			s.mu.Unlock()
			if idle {
				s.target.Close()
				delete(udpSessions, k)
			}
		}
		udpMu.Unlock()
	}
}

func lookupSession(sid []byte) (*udpSession, string) {
	suffix := string(sid)
	udpMu.Lock()
	defer udpMu.Unlock()
	for k, v := range udpSessions {
		if len(k) > 8 && k[len(k)-8:] == suffix {
			return v, k
		}
	}
	return nil, ""
}

func openDgram(sk, sid []byte, pkt []byte) (flags byte, seq uint32, data []byte, ok bool) {
	// total must be a valid class; pt budget = total-25-16, data ≤ budget-2
	if !validClass(udpClasses, len(pkt)) || len(pkt) < 8+12+1+4+2+16 {
		return 0, 0, nil, false
	}
	if string(pkt[:8]) != string(sid) {
		return 0, 0, nil, false
	}
	rnonce := pkt[8:20]
	flags = pkt[20]
	seq = binary.BigEndian.Uint32(pkt[21:25])
	ct := pkt[25:]
	a, _ := chacha20poly1305.New(sk)
	ad := make([]byte, 0, 13)
	ad = append(ad, sid...)
	ad = append(ad, flags)
	ad = append(ad, pkt[21:25]...)
	pt, err := a.Open(nil, rnonce, ct, ad)
	if err != nil {
		return 0, 0, nil, false
	}
	if len(pt) < 2 {
		return 0, 0, nil, false
	}
	ln := int(binary.BigEndian.Uint16(pt[:2]))
	budget := len(pkt) - 25 - 16
	if ln < 0 || 2+ln > budget || 2+ln > len(pt) {
		return 0, 0, nil, false
	}
	return flags, seq, pt[2 : 2+ln], true
}

func udpPump(conn *net.UDPConn, key string, addr *net.UDPAddr, sid, sk []byte, s *udpSession) {
	buf := make([]byte, udpMaxPayload)
	for {
		s.target.SetDeadline(time.Now().Add(3 * time.Minute))
		n, err := s.target.Read(buf)
		if err != nil || n == 0 {
			break
		}
		s.mu.Lock()
		seq := s.sendSeq
		s.sendSeq++
		s.last = time.Now()
		key := sk
		if !s.peerReady {
			key = s.sk0
		}
		s.mu.Unlock()
		total := pickClass(udpClasses)
		budget := total - 25 - 16
		off := 0
		for off < n {
			end := off + budget - 2
			if end > n {
				end = n
			}
			pt := make([]byte, budget)
			binary.BigEndian.PutUint16(pt[:2], uint16(end-off))
			copy(pt[2:], buf[off:end])
			if _, err := rand.Read(pt[2+end-off:]); err != nil {
				break
			}
			rnonce := make([]byte, 12)
			if _, err := rand.Read(rnonce); err != nil {
				break
			}
			a, _ := chacha20poly1305.New(key)
			ad := append(append(append([]byte(nil), sid...), 0), uint32be(seq)...)
			ct := a.Seal(nil, rnonce, pt, ad)
			out := make([]byte, 0, total)
			out = append(out, sid...)
			out = append(out, rnonce...)
			out = append(out, 0)
			out = append(out, uint32be(seq)...)
			out = append(out, ct...)
			conn.WriteToUDP(out, addr)
			seq++
			s.mu.Lock()
			s.sendSeq = seq
			s.mu.Unlock()
			off = end
		}
	}
	udpMu.Lock()
	if cur, ok := udpSessions[key]; ok && cur == s {
		delete(udpSessions, key)
	}
	udpMu.Unlock()
}

func uint32be(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func deliverUDP(s *udpSession, seq uint32, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = time.Now()
	if seq < s.expect {
		return
	}
	write := func(d []byte) bool {
		s.target.SetDeadline(time.Now().Add(30 * time.Second))
		_, err := s.target.Write(d)
		return err == nil
	}
	if seq == s.expect {
		if !write(data) {
			return
		}
		s.expect++
		for {
			d, ok := s.pending[s.expect]
			if !ok {
				break
			}
			delete(s.pending, s.expect)
			if !write(d) {
				return
			}
			s.expect++
		}
		s.gapSince = time.Time{}
		return
	}
	if len(s.pending) < 64 {
		if _, dup := s.pending[seq]; !dup {
			s.pending[seq] = data
		}
	}
	if s.gapSince.IsZero() {
		s.gapSince = time.Now()
	} else if time.Since(s.gapSince) > udpGap {
		min := seq
		for k := range s.pending {
			if k < min {
				min = k
			}
		}
		for s.expect < min {
			s.expect++
		}
		for {
			d, ok := s.pending[s.expect]
			if !ok {
				break
			}
			delete(s.pending, s.expect)
			if !write(d) {
				return
			}
			s.expect++
		}
		s.gapSince = time.Time{}
	}
}

// helloReply builds a class-sized server hello response.
func helloReply(sid, ephS, ephC, nonce []byte, total int) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte{version})
	m.Write(ephS)
	m.Write(ephC)
	m.Write(nonce)
	m.Write(sid)
	out := make([]byte, 0, total)
	out = append(out, sid...)
	out = append(out, ephS...)
	out = append(out, m.Sum(nil)[:16]...)
	pad := make([]byte, total-len(out))
	if _, err := rand.Read(pad); err != nil {
		panic(err)
	}
	return append(out, pad...)
}

func handleUDP(conn *net.UDPConn, addr *net.UDPAddr, pkt []byte) {
	if !validClass(udpClasses, len(pkt)) {
		return
	}
	// data datagram? (with grace for the creation race)
	if len(pkt) >= 8 {
		if s, _ := lookupSession(pkt[:8]); s != nil {
			if openDeliver(s, pkt) {
				return
			}
			return
		}
		if pkt[0] != version {
			for i := 0; i < 4; i++ {
				time.Sleep(50 * time.Millisecond)
				if s, _ := lookupSession(pkt[:8]); s != nil {
					openDeliver(s, pkt)
					return
				}
			}
			return
		}
	}
	// hello: ver(1) magic(4) nonceC(16) ephC(32) tag(16) sid(8) seq(4)
	//   flags(1) AEAD[pt = atyp+addr+port+pad, nonce=nonceC[:12]]
	if pkt[0] != version {
		return
	}
	total := len(pkt)
	budget := total - 82 - 16 // header 82, tag 16
	if budget < 2 {
		return
	}
	hsNonce := append([]byte(nil), pkt[5:21]...)
	ephC := append([]byte(nil), pkt[21:53]...)
	m := hmac.New(sha256.New, psk)
	m.Write(pkt[:53])
	if !hmac.Equal(m.Sum(nil)[:16], pkt[53:69]) {
		return
	}
	sid := append([]byte(nil), pkt[69:77]...)
	seq := binary.BigEndian.Uint32(pkt[77:81])
	flags := pkt[81]
	if flags&1 == 0 {
		return
	}
	if s, _ := lookupSession(sid); s != nil {
		// hello retransmit (client missed our reply): resend it
		conn.WriteToUDP(helloReply(s.sid, s.ephS, s.ephC, s.hsNonce, pickClass(udpClasses)), addr)
		return
	}
	if nonceSeen(hsNonce) {
		return
	}
	sk0 := hsKey(hsNonce)
	a, _ := chacha20poly1305.New(sk0)
	ad := append(append(append([]byte(nil), sid...), flags), pkt[77:81]...)
	pt, err := a.Open(nil, hsNonce[:12], pkt[82:], ad)
	if err != nil || len(pt) != budget {
		return
	}
	host, rest, ok := parseAddr(pt)
	if !ok || len(rest) < 2 {
		return
	}
	_ = seq
	target := host + ":" + itoa(int(binary.BigEndian.Uint16(rest[:2])))
	t, err := net.DialTimeout("tcp", target, dialTO)
	if err != nil {
		return
	}
	ephSPriv, ephSPub := genEphemeral()
	shared, err := curve25519.X25519(ephSPriv, ephC)
	if err != nil {
		t.Close()
		return
	}
	sk := fsKey(shared)
	key := addr.String() + "|" + string(sid)
	udpMu.Lock()
	if old, dup := udpSessions[key]; dup {
		old.target.Close()
	}
	s := &udpSession{target: t, pending: map[uint32][]byte{}, last: time.Now(),
		sk: append([]byte(nil), sk...), sk0: append([]byte(nil), sk0...),
		ephS: ephSPub, ephC: ephC, hsNonce: hsNonce, sid: sid}
	udpSessions[key] = s
	udpMu.Unlock()
	conn.WriteToUDP(helloReply(sid, ephSPub, ephC, hsNonce, pickClass(udpClasses)), addr)
	go udpPump(conn, key, addr, sid, s.sk, s)
}

// openDeliver opens one data datagram (FS key, or hello key for early
// traffic) and delivers it.
func openDeliver(s *udpSession, pkt []byte) bool {
	s.mu.Lock()
	sk := s.sk
	sk0 := s.sk0
	s.mu.Unlock()
	if flags, seq, data, ok := openDgram(sk, pkt[:8], pkt); ok {
		_ = flags
		s.mu.Lock()
		s.peerReady = true
		s.mu.Unlock()
		deliverUDP(s, seq, data)
		return true
	}
	if sk0 == nil {
		return false
	}
	if flags, seq, data, ok := openDgram(sk0, pkt[:8], pkt); ok {
		_ = flags
		deliverUDP(s, seq, data)
		return true
	}
	return false
}

func udpLoop(uconn *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := uconn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		go handleUDP(uconn, addr, pkt)
	}
}

func main() {
	mode := os.Getenv("SPECTER_TRANSPORT") // tcp | udp | both (default both)
	var ln net.Listener
	if mode != "udp" {
		var err error
		ln, err = net.Listen("tcp", listenAddr())
		if err != nil {
			panic(err)
		}
	}
	if mode != "tcp" {
		uaddr, err := net.ResolveUDPAddr("udp", listenAddr())
		if err != nil {
			panic(err)
		}
		uconn, err := net.ListenUDP("udp", uaddr)
		if err != nil {
			panic(err)
		}
		go udpLoop(uconn)
	}
	if ln == nil {
		select {} // UDP-only mode: just wait
	}
	go nonceSweeper()
	go udpReaper()
	sem := make(chan struct{}, maxConns)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		select {
		case sem <- struct{}{}:
			go handleTCP(c, sem)
		default:
			c.Close()
		}
	}
}
