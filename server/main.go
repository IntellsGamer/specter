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
	version   = 0x02
	cellSize  = 1024
	cellPT    = 996
	cellData  = 994
	dgramSize = 1280
	maxConns  = 1024
	dialTO    = 10 * time.Second
	nonceTTL  = 10 * time.Minute
	udpIdle   = 120 * time.Second
	udpGap    = 500 * time.Millisecond

	udpMaxPayload = 1200
	dgramPT       = 1239
	firstPT       = 1214
)

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

// ---------- TCP cells (unchanged wire, v3 session key) ----------

func sealCell(sk, data []byte) []byte {
	if len(data) > cellData {
		data = data[:cellData]
	}
	pt := make([]byte, cellPT)
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
	out := make([]byte, 0, cellSize)
	out = append(out, rnonce...)
	out = append(out, a.Seal(nil, rnonce, pt, nil)...)
	return out
}

func openCell(sk, cell []byte) ([]byte, error) {
	if len(cell) != cellSize {
		return nil, io.ErrUnexpectedEOF
	}
	a, _ := chacha20poly1305.New(sk)
	pt, err := a.Open(nil, cell[:12], cell[12:], nil)
	if err != nil {
		return nil, err
	}
	ln := int(binary.BigEndian.Uint16(pt[:2]))
	if ln < 0 || ln > cellData {
		return nil, io.ErrUnexpectedEOF
	}
	return pt[2 : 2+ln], nil
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
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.Write(serverReply(ephSPub, ephC, nonce)); err != nil {
		return
	}
	first := make([]byte, cellSize)
	if _, err := io.ReadFull(c, first); err != nil {
		return
	}
	tgt, err := openCell(sk, first)
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
		cell := make([]byte, cellSize)
		for {
			if _, err := io.ReadFull(c, cell); err != nil {
				return
			}
			d, err := openCell(sk, cell)
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
		buf := make([]byte, cellData)
		for {
			t.SetDeadline(time.Now().Add(3 * time.Minute))
			n, err := t.Read(buf)
			if err != nil || n == 0 {
				return
			}
			c.SetDeadline(time.Now().Add(3 * time.Minute))
			if _, err := c.Write(sealCell(sk, buf[:n])); err != nil {
				return
			}
		}
	}()
	<-done
}

// ---------- UDP ----------

type udpSession struct {
	target  net.Conn
	sendSeq uint32
	expect  uint32
	pending map[uint32][]byte
	gapSince time.Time
	last    time.Time
	sk      []byte
	ephS    []byte
	ephC    []byte
	hsNonce []byte
	sid     []byte
	mu      sync.Mutex
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
	if len(pkt) < 8+12+1+4+2+16 {
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
	if ln < 0 || 2+ln > len(pt) {
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
		s.mu.Unlock()
		pt := make([]byte, dgramPT)
		binary.BigEndian.PutUint16(pt[:2], uint16(n))
		copy(pt[2:], buf[:n])
		if _, err := rand.Read(pt[2+n:]); err != nil {
			break
		}
		rnonce := make([]byte, 12)
		if _, err := rand.Read(rnonce); err != nil {
			break
		}
		a, _ := chacha20poly1305.New(sk)
		ad := append(append(append([]byte(nil), sid...), 0), uint32be(seq)...)
		ct := a.Seal(nil, rnonce, pt, ad)
		out := make([]byte, 0, dgramSize)
		out = append(out, sid...)
		out = append(out, rnonce...)
		out = append(out, 0)
		out = append(out, uint32be(seq)...)
		out = append(out, ct...)
		conn.WriteToUDP(out, addr)
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

// helloReply builds the fixed-size server hello response.
func helloReply(sid, ephS, ephC, nonce []byte) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte{version})
	m.Write(ephS)
	m.Write(ephC)
	m.Write(nonce)
	m.Write(sid)
	out := make([]byte, 0, dgramSize)
	out = append(out, sid...)
	out = append(out, ephS...)
	out = append(out, m.Sum(nil)[:16]...)
	pad := make([]byte, dgramSize-len(out))
	if _, err := rand.Read(pad); err != nil {
		panic(err)
	}
	return append(out, pad...)
}

func handleUDP(conn *net.UDPConn, addr *net.UDPAddr, pkt []byte) {
	if len(pkt) != dgramSize {
		return
	}
	// data datagram? (with grace for the creation race)
	if len(pkt) >= 8 {
		if s, _ := lookupSession(pkt[:8]); s != nil {
			flags, seq, data, ok := openDgram(s.sk, pkt[:8], pkt)
			if !ok {
				return
			}
			_ = flags
			deliverUDP(s, seq, data)
			return
		}
		if pkt[0] != version {
			for i := 0; i < 4; i++ {
				time.Sleep(50 * time.Millisecond)
				if s, _ := lookupSession(pkt[:8]); s != nil {
					flags, seq, data, ok := openDgram(s.sk, pkt[:8], pkt)
					if !ok {
						return
					}
					_ = flags
					deliverUDP(s, seq, data)
					return
				}
			}
			return
		}
	}
	// hello: ver(1) magic(4) nonceC(16) ephC(32) tag(16) sid(8) seq(4) flags(1) AEAD
	if pkt[0] != version {
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
		conn.WriteToUDP(helloReply(s.sid, s.ephS, s.ephC, s.hsNonce), addr)
		return
	}
	if nonceSeen(hsNonce) {
		return
	}
	sk0 := hsKey(hsNonce)
	a, _ := chacha20poly1305.New(sk0)
	ad := append(append(append([]byte(nil), sid...), flags), pkt[77:81]...)
	pt, err := a.Open(nil, hsNonce[:12], pkt[82:], ad)
	if err != nil {
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
		sk: append([]byte(nil), sk...), ephS: ephSPub, ephC: ephC,
		hsNonce: hsNonce, sid: sid}
	udpSessions[key] = s
	udpMu.Unlock()
	conn.WriteToUDP(helloReply(sid, ephSPub, ephC, hsNonce), addr)
	go udpPump(conn, key, addr, sid, s.sk, s)
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
	ln, err := net.Listen("tcp", listenAddr())
	if err != nil {
		panic(err)
	}
	// SPECTER_TRANSPORT=tcp -> TCP only; anything else -> TCP+UDP.
	if os.Getenv("SPECTER_TRANSPORT") != "tcp" {
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
