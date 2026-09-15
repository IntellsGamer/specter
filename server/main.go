package main

// Specter server: toy obfuscated TCP relay. NOT audited crypto.
// Configure with environment: SPECTER_PSK (hex, required), SPECTER_LISTEN (default ":43117").

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

var psk = mustPSK()

func mustPSK() []byte {
	raw := os.Getenv("SPECTER_PSK")
	if raw == "" {
		log.Fatal("SPECTER_PSK is not set (32-byte key as 64 hex chars)")
	}
	b, err := hex.DecodeString(raw)
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
var magic = []byte{'R', '1', 0x07, 0x9d}

const (
	maxFrame = 16383
	maxConns = 1024
	dialTO   = 10 * time.Second
)

type xstream struct {
	nonce []byte
	dir   byte
	ctr   uint32
	buf   []byte
}

func (x *xstream) run(data []byte) []byte {
	out := make([]byte, len(data))
	off := 0
	for off < len(data) {
		if len(x.buf) == 0 {
			h := sha256.New()
			h.Write(psk)
			h.Write(x.nonce)
			h.Write([]byte{x.dir})
			var c [4]byte
			binary.BigEndian.PutUint32(c[:], x.ctr)
			h.Write(c[:])
			x.buf = h.Sum(nil)
			x.ctr++
		}
		n := len(x.buf)
		if rem := len(data) - off; rem < n {
			n = rem
		}
		for i := 0; i < n; i++ {
			out[off+i] = data[off+i] ^ x.buf[i]
		}
		// advance
		off += n
		x.buf = x.buf[n:]
	}
	return out
}

func readFrame(r io.Reader, x *xstream) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	ln := int(binary.BigEndian.Uint16(hdr[:]))
	if ln == 0 || ln > maxFrame {
		return nil, io.ErrUnexpectedEOF
	}
	enc := make([]byte, ln)
	if _, err := io.ReadFull(r, enc); err != nil {
		return nil, err
	}
	return x.run(enc), nil
}

func writeFrame(w io.Writer, x *xstream, data []byte) error {
	enc := x.run(data)
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(enc)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(enc)
	return err
}

func handle(c net.Conn, sem chan struct{}) {
	defer c.Close()
	defer func() { <-sem }()

	head := make([]byte, 36)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	if string(head[:4]) != string(magic) {
		return
	}
	nonce := append([]byte(nil), head[4:20]...)
	m := hmac.New(sha256.New, psk)
	m.Write(magic)
	m.Write(nonce)
	if !hmac.Equal(m.Sum(nil)[:16], head[20:36]) {
		return
	}
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(c, atyp); err != nil {
		return
	}
	var host string
	switch atyp[0] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	target := host + ":" + itoa(int(binary.BigEndian.Uint16(pb)))
	t, err := net.DialTimeout("tcp", target, dialTO)
	if err != nil {
		return
	}
	defer t.Close()

	up := &xstream{nonce: nonce, dir: 0}
	down := &xstream{nonce: nonce, dir: 1}
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		for {
			d, err := readFrame(c, up)
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
		buf := make([]byte, maxFrame)
		for {
			t.SetDeadline(time.Now().Add(3 * time.Minute))
			n, err := t.Read(buf)
			if err != nil || n == 0 {
				return
			}
			c.SetDeadline(time.Now().Add(3 * time.Minute))
			if err := writeFrame(c, down, buf[:n]); err != nil {
				return
			}
		}
	}()
	<-done
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

// ---------- UDP transport ----------
// Datagram client->server:
//   MAGIC(4) nonce(16) tag(16) seq u32 atyp addr port u16 flen u16 payload
// Datagram server->client:
//   MAGIC(4) nonce(16) seq u32 flen u16 payload
// Payload crypto is per-datagram (loss/reorder safe):
//   block(nonce,dir,seq,blk) = SHA256(PSK||nonce||dir||BE32(seq)||BE32(blk))

const (
	udpMaxPayload = 1200
	udpIdle       = 120 * time.Second
	udpGapWait    = 500 * time.Millisecond
)

func ksU(nonce []byte, dir byte, seq, blk uint32) []byte {
	h := sha256.New()
	h.Write(psk)
	h.Write(nonce)
	h.Write([]byte{dir})
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], seq)
	h.Write(b[:])
	binary.BigEndian.PutUint32(b[:], blk)
	h.Write(b[:])
	return h.Sum(nil)
}

func cryptU(nonce []byte, dir byte, seq uint32, data []byte) []byte {
	out := make([]byte, len(data))
	var blk uint32
	off := 0
	for off < len(data) {
		ks := ksU(nonce, dir, seq, blk)
		blk++
		n := len(ks)
		if rem := len(data) - off; rem < n {
			n = rem
		}
		for i := 0; i < n; i++ {
			out[off+i] = data[off+i] ^ ks[i]
		}
		off += n
	}
	return out
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

type udpSession struct {
	target  net.Conn
	sendSeq uint32
	expect  uint32
	pending map[uint32][]byte
	gapSince time.Time
	last    time.Time
	mu      sync.Mutex
}

var (
	udpMu       sync.Mutex
	udpSessions = map[string]*udpSession{}
)

func udpKey(addr *net.UDPAddr, nonce []byte) string {
	return addr.String() + "|" + hex.EncodeToString(nonce)
}

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

func udpPump(conn *net.UDPConn, key string, addr *net.UDPAddr, nonce []byte, s *udpSession) {
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
		s.mu.Unlock()
		enc := cryptU(nonce, 1, seq, buf[:n])
		out := make([]byte, 0, 4+16+4+2+len(enc))
		out = append(out, magic...)
		out = append(out, nonce...)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], seq)
		out = append(out, b[:]...)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(enc)))
		out = append(out, l[:]...)
		out = append(out, enc...)
		conn.WriteToUDP(out, addr)
	}
	udpMu.Lock()
	if cur, ok := udpSessions[key]; ok && cur == s {
		delete(udpSessions, key)
	}
	udpMu.Unlock()
}

func handleUDP(conn *net.UDPConn, addr *net.UDPAddr, pkt []byte) {
	if len(pkt) < 4+16+16+4+1+2+2 {
		return
	}
	if string(pkt[:4]) != string(magic) {
		return
	}
	nonce := append([]byte(nil), pkt[4:20]...)
	m := hmac.New(sha256.New, psk)
	m.Write(magic)
	m.Write(nonce)
	if !hmac.Equal(m.Sum(nil)[:16], pkt[20:36]) {
		return
	}
	seq := binary.BigEndian.Uint32(pkt[36:40])
	host, rest, ok := parseAddr(pkt[40:])
	if !ok || len(rest) < 4 {
		return
	}
	port := binary.BigEndian.Uint16(rest[:2])
	rest = rest[2:]
	flen := int(binary.BigEndian.Uint16(rest[:2]))
	rest = rest[2:]
	if len(rest) < flen || flen > udpMaxPayload {
		return
	}
	plain := cryptU(nonce, 0, seq, rest[:flen])

	key := udpKey(addr, nonce)
	udpMu.Lock()
	s, found := udpSessions[key]
	if !found {
		t, err := net.DialTimeout("tcp", host+":"+itoa(int(port)), dialTO)
		if err != nil {
			udpMu.Unlock()
			return
		}
		s = &udpSession{target: t, pending: map[uint32][]byte{}, last: time.Now()}
		udpSessions[key] = s
		udpMu.Unlock()
		go udpPump(conn, key, addr, nonce, s)
	} else {
		udpMu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = time.Now()
	if seq < s.expect {
		return
	}
	if seq == s.expect {
		s.target.SetDeadline(time.Now().Add(3 * time.Minute))
		if _, err := s.target.Write(plain); err != nil {
			return
		}
		s.expect++
		for {
			d, ok := s.pending[s.expect]
			if !ok {
				break
			}
			delete(s.pending, s.expect)
			if _, err := s.target.Write(d); err != nil {
				return
			}
			s.expect++
		}
		s.gapSince = time.Time{}
		return
	}
	if len(s.pending) >= 64 {
		return
	}
	if _, dup := s.pending[seq]; !dup {
		s.pending[seq] = plain
	}
	if s.gapSince.IsZero() {
		s.gapSince = time.Now()
	} else if time.Since(s.gapSince) > udpGapWait {
		// gap stuck: skip to smallest buffered seq
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
			if _, err := s.target.Write(d); err != nil {
				return
			}
			s.expect++
		}
		s.gapSince = time.Time{}
	}
}

func main() {
	ln, err := net.Listen("tcp", listenAddr())
	if err != nil {
		panic(err)
	}
	uaddr, err := net.ResolveUDPAddr("udp", listenAddr())
	if err != nil {
		panic(err)
	}
	uconn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		panic(err)
	}
	go udpReaper()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := uconn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			pkt := append([]byte(nil), buf[:n]...)
			go handleUDP(uconn, addr, pkt)
		}
	}()
	sem := make(chan struct{}, maxConns)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		select {
		case sem <- struct{}{}:
			go handle(c, sem)
		default:
			c.Close()
		}
	}
}
