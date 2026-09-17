package main

// Specter v3.2 client (Go): SOCKS5 on 127.0.0.1:10867 -> Specter AEAD protocol.
// Config: config.json (server/port/psk/transport tcp|udp|auto) or argv path.
// Env overrides: SPECTER_SERVER/PORT/PSK/TRANSPORT.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	version     = 0x03
	socksListen = "127.0.0.1:10867"
)

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

// --- latency fixes ---

const (
	// First N bytes of a connection use the smallest class to minimise
	// padding-on-wire and time-to-first-byte. After that, randomise for
	// obfuscation as before.
	earlyBytesThreshold = 4096
	// Out-of-order gap skip: 100ms instead of 300ms. Single loss must not
	// stall a TLS handshake for a third of a second.
	udpGapFast = 100 * time.Millisecond
	// Hello retransmit interval: 150ms instead of 1s.
	helloRetryInterval = 150 * time.Millisecond
	helloTimeout       = 8 * time.Second
	// Transport pinning: race once, reuse winner for 5min.
	pinTTL = 5 * time.Minute
)

func tuneTCP(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

// pickClassLatency returns the smallest class for the first earlyBytesThreshold
// bytes (TTFB-sensitive TLS/DNS/small HTTP), then random as before.
func pickClassLatency(classes []int, bytesSent int) int {
	if bytesSent < earlyBytesThreshold {
		return classes[0]
	}
	return pickClass(classes)
}

var pinned = struct {
	sync.Mutex
	transport string
	expires   time.Time
}{}

func getPinned() string {
	pinned.Lock()
	defer pinned.Unlock()
	if time.Now().Before(pinned.expires) && pinned.transport != "" {
		return pinned.transport
	}
	return ""
}

func setPinned(t string) {
	pinned.Lock()
	pinned.transport = t
	pinned.expires = time.Now().Add(pinTTL)
	pinned.Unlock()
}

type Config struct {
	Server    string `json:"server"`
	Port      int    `json:"port"`
	Psk       string `json:"psk"`
	Transport string `json:"transport"`
}

func loadConfig() (server string, port int, psk []byte, transport string) {
	path := ""
	if len(os.Args) > 1 && os.Args[1][0] != '-' {
		path = os.Args[1]
	} else if exe, err := os.Executable(); err == nil {
		path = filepath.Join(filepath.Dir(exe), "config.json")
	}
	var cfg Config
	cfgPath := path
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &cfg)
	}
	if v := os.Getenv("SPECTER_SERVER"); v != "" {
		cfg.Server = v
	}
	if v := os.Getenv("SPECTER_PORT"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.Port)
	}
	if v := os.Getenv("SPECTER_PSK"); v != "" {
		cfg.Psk = v
	}
	if v := os.Getenv("SPECTER_TRANSPORT"); v != "" {
		cfg.Transport = v
	}
	if cfg.Transport == "" {
		cfg.Transport = "auto"
	}
	if cfg.Transport != "tcp" && cfg.Transport != "udp" && cfg.Transport != "auto" {
		log.Fatal(`transport must be "tcp", "udp" or "auto"`)
	}
	missing := cfg.Server == "" || cfg.Server == "YOUR_SERVER_IP" ||
		cfg.Psk == "" || (len(cfg.Psk) >= 7 && cfg.Psk[:7] == "REPLACE")
	if missing {
		if cfgPath != "" {
			if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
				dummy, _ := json.MarshalIndent(Config{
					Server: "203.0.113.10", Port: 43117,
					Psk:       "REPLACE_WITH_64_HEX_CHARS_FROM_SERVER",
					Transport: "auto",
				}, "", "  ")
				_ = os.WriteFile(cfgPath, append(dummy, '\n'), 0600)
			}
		}
		msg := "I wrote a dummy config.json next to the app — fill in server/port/psk and run me again."
		notifyUser("Specter", msg)
		log.Fatal("no server/key set — dummy config.json created, fill it in and rerun")
	}
	if cfg.Port == 0 {
		cfg.Port = 43117
	}
	b, err := hex.DecodeString(cfg.Psk)
	if err != nil || len(b) != 32 {
		log.Fatal("psk must be 64 hex chars")
	}
	return cfg.Server, cfg.Port, b, cfg.Transport
}

func fsKey(psk, shared []byte) []byte {
	r := hkdf.New(func() hash.Hash { return sha256.New() }, shared, psk, []byte("specter-v3"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(err)
	}
	return out
}

func hsKey(psk, hsNonce []byte) []byte {
	h := sha256.New()
	h.Write(psk)
	h.Write([]byte("specter-v3-hs"))
	h.Write(hsNonce)
	return h.Sum(nil)
}

func genEphemeral() (priv, pub []byte) {
	priv = randBytes(32)
	var err error
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return priv, pub
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// ---------- TCP records ----------

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
	rnonce := randBytes(12)
	out := make([]byte, 0, total)
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(total-2))
	out = append(out, hdr[:]...)
	out = append(out, rnonce...)
	out = append(out, a.Seal(nil, rnonce, pt, nil)...)
	return out
}

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
	a, _ := chacha20poly1305.New(sk)
	pt, err := a.Open(nil, body[:12], body[12:], nil)
	if err != nil {
		return nil, err
	}
	ln := int(binary.BigEndian.Uint16(pt[:2]))
	budget := total - 2 - 12 - 16
	if ln < 0 || 2+ln > budget || 2+ln > len(pt) {
		return nil, io.ErrUnexpectedEOF
	}
	return pt[2 : 2+ln], nil
}

// sealRecordFast reuses the per-connection AEAD and does a single rand.Read
// for nonce+pad instead of two syscalls.
func sealRecordFast(aead interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
}, data []byte, total int) []byte {
	budget := total - 2 - 12 - 16
	if len(data) > budget-2 {
		data = data[:budget-2]
	}
	padLen := budget - 2 - len(data)
	// one CSPRNG read for nonce (12) + pad
	tmp := make([]byte, 12+padLen)
	if _, err := rand.Read(tmp); err != nil {
		panic(err)
	}
	rnonce := tmp[:12]
	pt := make([]byte, budget)
	binary.BigEndian.PutUint16(pt[:2], uint16(len(data)))
	copy(pt[2:], data)
	copy(pt[2+len(data):], tmp[12:])
	out := make([]byte, 0, total)
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(total-2))
	out = append(out, hdr[:]...)
	out = append(out, rnonce...)
	out = append(out, aead.Seal(nil, rnonce, pt, nil)...)
	return out
}

func readRecordFast(r io.Reader, aead interface {
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}) ([]byte, error) {
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
	pt, err := aead.Open(nil, body[:12], body[12:], nil)
	if err != nil {
		return nil, err
	}
	ln := int(binary.BigEndian.Uint16(pt[:2]))
	budget := total - 2 - 12 - 16
	if ln < 0 || 2+ln > budget || 2+ln > len(pt) {
		return nil, io.ErrUnexpectedEOF
	}
	return pt[2 : 2+ln], nil
}

// ---------- established sessions ----------

type established struct {
	transport string
	up        net.Conn  // tcp
	us        *net.UDPConn // udp
	sk        []byte
	sid       []byte // udp
	sk0       []byte // udp hello key (kept for completeness)
}

// handshakeTCP performs hs + first record (target, sk0) in one flight,
// verifies the reply, and returns a live session.
func handshakeTCP(server string, port int, psk []byte, atyp byte, addr, portb []byte) (*established, error) {
	magic := randBytes(4)
	nonce := randBytes(16)
	ephPriv, ephPub := genEphemeral()
	m := hmac.New(sha256.New, psk)
	m.Write([]byte{version})
	m.Write(magic)
	m.Write(nonce)
	m.Write(ephPub)
	tag := m.Sum(nil)[:16]
	sk0 := hsKey(psk, nonce)
	up, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", server, port), 10*time.Second)
	if err != nil {
		return nil, err
	}
	tuneTCP(up)
	hs := make([]byte, 0, 69)
	hs = append(hs, version)
	hs = append(hs, magic...)
	hs = append(hs, nonce...)
	hs = append(hs, ephPub...)
	hs = append(hs, tag...)
	tgt := append([]byte{atyp}, addr...)
	tgt = append(tgt, portb...)
	// latency: smallest class for target (usually <100B) avoids 1KB pad on handshake
	flight := append(hs, sealRecord(sk0, tgt, tcpClasses[0])...)
	up.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := up.Write(flight); err != nil {
		up.Close()
		return nil, err
	}
	rep := make([]byte, 49)
	if _, err := io.ReadFull(up, rep); err != nil {
		up.Close()
		return nil, err
	}
	if rep[0] != version {
		up.Close()
		return nil, fmt.Errorf("bad version")
	}
	ephS := rep[1:33]
	m2 := hmac.New(sha256.New, psk)
	m2.Write([]byte{version})
	m2.Write(ephS)
	m2.Write(ephPub)
	m2.Write(nonce)
	if !hmac.Equal(m2.Sum(nil)[:16], rep[33:49]) {
		up.Close()
		return nil, fmt.Errorf("bad reply tag")
	}
	shared, err := curve25519.X25519(ephPriv, ephS)
	if err != nil {
		up.Close()
		return nil, err
	}
	up.SetDeadline(time.Time{})
	return &established{transport: "tcp", up: up, sk: fsKey(psk, shared)}, nil
}

// handshakeTCPEarly overlaps browseresty with Specter RTT: it dials+sends the
// flight, immediately replies SOCKS success so the browser sends ClientHello
// while we wait for the server reply. Browser bytes stay in kernel buffer
// until relay starts. Saves ~1 RTT per connection.
func handshakeTCPEarly(app net.Conn, server string, port int, psk []byte, atyp byte, addr, portb []byte) (*established, error) {
	magic := randBytes(4)
	nonce := randBytes(16)
	ephPriv, ephPub := genEphemeral()
	m := hmac.New(sha256.New, psk)
	m.Write([]byte{version})
	m.Write(magic)
	m.Write(nonce)
	m.Write(ephPub)
	tag := m.Sum(nil)[:16]
	sk0 := hsKey(psk, nonce)
	up, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", server, port), 10*time.Second)
	if err != nil {
		return nil, err
	}
	tuneTCP(up)
	tuneTCP(app)
	hs := make([]byte, 0, 69)
	hs = append(hs, version)
	hs = append(hs, magic...)
	hs = append(hs, nonce...)
	hs = append(hs, ephPub...)
	hs = append(hs, tag...)
	tgt := append([]byte{atyp}, addr...)
	tgt = append(tgt, portb...)
	flight := append(hs, sealRecord(sk0, tgt, tcpClasses[0])...)
	up.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := up.Write(flight); err != nil {
		up.Close()
		return nil, err
	}
	// Early SOCKS reply BEFORE waiting for server reply.
	app.SetDeadline(time.Now().Add(3 * time.Minute))
	if _, err := app.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		up.Close()
		return nil, err
	}
	rep := make([]byte, 49)
	if _, err := io.ReadFull(up, rep); err != nil {
		up.Close()
		return nil, err
	}
	if rep[0] != version {
		up.Close()
		return nil, fmt.Errorf("bad version")
	}
	ephS := rep[1:33]
	m2 := hmac.New(sha256.New, psk)
	m2.Write([]byte{version})
	m2.Write(ephS)
	m2.Write(ephPub)
	m2.Write(nonce)
	if !hmac.Equal(m2.Sum(nil)[:16], rep[33:49]) {
		up.Close()
		return nil, fmt.Errorf("bad reply tag")
	}
	shared, err := curve25519.X25519(ephPriv, ephS)
	if err != nil {
		up.Close()
		return nil, err
	}
	up.SetDeadline(time.Time{})
	return &established{transport: "tcp", up: up, sk: fsKey(psk, shared)}, nil
}

func relayTCP(app net.Conn, e *established) {
	defer app.Close()
	defer e.up.Close()
	tuneTCP(app)
	tuneTCP(e.up)
	aead, _ := chacha20poly1305.New(e.sk)
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			d, err := readRecordFast(e.up, aead)
			if err != nil {
				return
			}
			e.up.SetDeadline(time.Now().Add(3 * time.Minute))
			app.SetDeadline(time.Now().Add(3 * time.Minute))
			if _, err := app.Write(d); err != nil {
				return
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 1388)
		sent := 0
		for {
			app.SetDeadline(time.Now().Add(3 * time.Minute))
			n, err := app.Read(buf)
			if err != nil || n == 0 {
				return
			}
			e.up.SetDeadline(time.Now().Add(3 * time.Minute))
			off := 0
			for off < n {
				total := pickClassLatency(tcpClasses, sent)
				end := off + total - 2 - 12 - 16 - 2
				if end > n {
					end = n
				}
				if _, err := e.up.Write(sealRecordFast(aead, buf[off:end], total)); err != nil {
					return
				}
				sent += end - off
				off = end
			}
		}
	}()
	<-done
}

// sealDgram builds a class-sized data datagram.
func sealDgram(sk, sid, rnonce []byte, flags byte, seq uint32, data []byte, total int) []byte {
	budget := total - 25 - 16
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
	ad := make([]byte, 0, 13)
	ad = append(ad, sid...)
	ad = append(ad, flags)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], seq)
	ad = append(ad, b[:]...)
	ct := a.Seal(nil, rnonce, pt, ad)
	out := make([]byte, 0, total)
	out = append(out, sid...)
	out = append(out, rnonce...)
	out = append(out, flags)
	out = append(out, b[:]...)
	out = append(out, ct...)
	return out
}

// sealDgramFast reuses AEAD and does a single rand.Read for nonce+pad.
func sealDgramFast(aead interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
}, sid []byte, flags byte, seq uint32, data []byte, total int) []byte {
	budget := total - 25 - 16
	if len(data) > budget-2 {
		data = data[:budget-2]
	}
	padLen := budget - 2 - len(data)
	tmp := make([]byte, 12+padLen)
	if _, err := rand.Read(tmp); err != nil {
		panic(err)
	}
	rnonce := tmp[:12]
	pt := make([]byte, budget)
	binary.BigEndian.PutUint16(pt[:2], uint16(len(data)))
	copy(pt[2:], data)
	copy(pt[2+len(data):], tmp[12:])
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], seq)
	ad := make([]byte, 0, 13)
	ad = append(ad, sid...)
	ad = append(ad, flags)
	ad = append(ad, b[:]...)
	ct := aead.Seal(nil, rnonce, pt, ad)
	out := make([]byte, 0, total)
	out = append(out, sid...)
	out = append(out, rnonce...)
	out = append(out, flags)
	out = append(out, b[:]...)
	out = append(out, ct...)
	return out
}

// tuneUDP raises socket buffers so bursts don't collapse into loss.
func tuneUDP(c net.Conn) {
	if u, ok := c.(*net.UDPConn); ok {
		_ = u.SetReadBuffer(4 << 20)
		_ = u.SetWriteBuffer(4 << 20)
	}
}

// handshakeUDP performs hello + reply wait (retransmitting) and returns live session.
func handshakeUDP(server string, port int, psk []byte, atyp byte, addr, portb []byte) (*established, error) {
	us, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", server, port), 10*time.Second)
	if err != nil {
		return nil, err
	}
	tuneUDP(us)
	magic := randBytes(4)
	hsNonce := randBytes(16)
	ephPriv, ephPub := genEphemeral()
	m := hmac.New(sha256.New, psk)
	m.Write([]byte{version})
	m.Write(magic)
	m.Write(hsNonce)
	m.Write(ephPub)
	tag := m.Sum(nil)[:16]
	sk0 := hsKey(psk, hsNonce)
	sid := randBytes(8)
	target := append([]byte{atyp}, addr...)
	target = append(target, portb...)
	helloTotal := udpClasses[0]
	hbudget := helloTotal - 82 - 16
	hpt := make([]byte, hbudget)
	copy(hpt, target)
	if _, err := rand.Read(hpt[len(target):]); err != nil {
		us.Close()
		return nil, err
	}
	a, _ := chacha20poly1305.New(sk0)
	fad := make([]byte, 0, 13)
	fad = append(fad, sid...)
	fad = append(fad, 1)
	fad = append(fad, 0, 0, 0, 0)
	fct := a.Seal(nil, hsNonce[:12], hpt, fad)
	hello := make([]byte, 0, helloTotal)
	hello = append(hello, version)
	hello = append(hello, magic...)
	hello = append(hello, hsNonce...)
	hello = append(hello, ephPub...)
	hello = append(hello, tag...)
	hello = append(hello, sid...)
	hello = append(hello, 0, 0, 0, 0, 1)
	hello = append(hello, fct...)
	deadline := time.Now().Add(helloTimeout)
	for {
		us.SetDeadline(time.Now().Add(helloRetryInterval))
		if _, err := us.Write(hello); err != nil {
			us.Close()
			return nil, err
		}
		rep := make([]byte, 2048)
		us.SetDeadline(time.Now().Add(helloRetryInterval))
		n, err := us.Read(rep)
		if err != nil {
			if time.Now().After(deadline) {
				us.Close()
				return nil, fmt.Errorf("no hello reply")
			}
			continue
		}
		rep = rep[:n]
		if !validClass(udpClasses, len(rep)) || string(rep[:8]) != string(sid) {
			continue
		}
		ephS := rep[8:40]
		m2 := hmac.New(sha256.New, psk)
		m2.Write([]byte{version})
		m2.Write(ephS)
		m2.Write(ephPub)
		m2.Write(hsNonce)
		m2.Write(sid)
		if !hmac.Equal(m2.Sum(nil)[:16], rep[40:56]) {
			continue
		}
		shared, err := curve25519.X25519(ephPriv, ephS)
		if err != nil {
			us.Close()
			return nil, err
		}
		sk := fsKey(psk, shared)
		// sender starts immediately from here; early data handled by caller via sk0
		return &established{transport: "udp", us: us.(*net.UDPConn), sk: sk, sid: sid, sk0: sk0}, nil
	}
}

func relayUDP(app net.Conn, e *established) {
	defer app.Close()
	defer e.us.Close()
	sk := e.sk
	sid := e.sid
	tuneTCP(app)
	// reply already verified during handshake, so sk is live.
	aead, _ := chacha20poly1305.New(sk)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var seq uint32
		buf := make([]byte, 1200)
		sent := 0
		for {
			app.SetDeadline(time.Now().Add(3 * time.Minute))
			n, err := app.Read(buf)
			if err != nil || n == 0 {
				return
			}
			total := pickClassLatency(udpClasses, sent)
			budget := total - 25 - 16
			off := 0
			for off < n {
				end := off + budget - 2
				if end > n {
					end = n
				}
				dg := sealDgramFast(aead, sid, 0, seq, buf[off:end], total)
				seq++
				sent += end - off
				e.us.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, err := e.us.Write(dg); err != nil {
					return
				}
				off = end
			}
		}
	}()
	expect := uint32(0)
	pending := map[uint32][]byte{}
	var gapSince time.Time
	rbuf := make([]byte, 2048)
	a := aead
	for {
		select {
		case <-done:
			return
		default:
		}
		e.us.SetReadDeadline(time.Now().Add(3 * time.Minute))
		n, err := e.us.Read(rbuf)
		if err != nil {
			return
		}
		dg := rbuf[:n]
		if !validClass(udpClasses, len(dg)) || string(dg[:8]) != string(sid) {
			continue
		}
		pt, err := a.Open(nil, dg[8:20], dg[25:], append(append(append([]byte(nil), dg[:8]...), dg[20]), dg[21:25]...))
		if err != nil {
			continue
		}
		seq := binary.BigEndian.Uint32(dg[21:25])
		ln := int(binary.BigEndian.Uint16(pt[:2]))
		budget := len(dg) - 25 - 16
		if ln < 0 || 2+ln > budget || 2+ln > len(pt) {
			continue
		}
		data := append([]byte(nil), pt[2:2+ln]...)
		if seq < expect {
			continue
		}
		if _, dup := pending[seq]; dup {
			continue
		}
		if len(pending) < 64 {
			pending[seq] = data
		}
		drained := false
		for {
			d, ok := pending[expect]
			if !ok {
				break
			}
			delete(pending, expect)
			app.SetDeadline(time.Now().Add(3 * time.Minute))
			if _, err := app.Write(d); err != nil {
				return
			}
			expect++
			drained = true
		}
		if drained {
			gapSince = time.Time{}
		} else if len(pending) > 0 {
			if gapSince.IsZero() {
				gapSince = time.Now()
			} else if time.Since(gapSince) > udpGapFast {
				min := seq
				for k := range pending {
					if k < min {
						min = k
					}
				}
				expect = min
				gapSince = time.Time{}
			}
		}
	}
}

// udpLegPinned runs UDP with true 0-RTT: sender starts under sk0
// immediately, flips to sk once the hello reply verifies.
func udpLegPinned(app net.Conn, server string, port int, psk []byte, atyp byte, addr, portb []byte) {
	defer app.Close()
	us, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", server, port), 10*time.Second)
	if err != nil {
		return
	}
	defer us.Close()
	tuneUDP(us)
	magic := randBytes(4)
	hsNonce := randBytes(16)
	ephPriv, ephPub := genEphemeral()
	m := hmac.New(sha256.New, psk)
	m.Write([]byte{version})
	m.Write(magic)
	m.Write(hsNonce)
	m.Write(ephPub)
	tag := m.Sum(nil)[:16]
	sk0 := hsKey(psk, hsNonce)
	sid := randBytes(8)
	target := append([]byte{atyp}, addr...)
	target = append(target, portb...)
	total := udpClasses[0]
	budget := total - 82 - 16
	hpt := make([]byte, budget)
	copy(hpt, target)
	if _, err := rand.Read(hpt[len(target):]); err != nil {
		return
	}
	a0, _ := chacha20poly1305.New(sk0)
	fad := append(append(append([]byte(nil), sid...), 1), 0, 0, 0, 0)
	fct := a0.Seal(nil, hsNonce[:12], hpt, fad)
	hello := make([]byte, 0, total)
	hello = append(hello, version)
	hello = append(hello, magic...)
	hello = append(hello, hsNonce...)
	hello = append(hello, ephPub...)
	hello = append(hello, tag...)
	hello = append(hello, sid...)
	hello = append(hello, 0, 0, 0, 0, 1)
	hello = append(hello, fct...)
	type keyState struct {
		sync.Mutex
		aead  interface {
			Seal(dst, nonce, plaintext, additionalData []byte) []byte
			Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		}
		early bool
	}
	ks := &keyState{aead: a0, early: true}
	if _, err := us.Write(hello); err != nil {
		return
	}
	// Single reader from here on: reply detection + data share this loop,
	// so no datagram is ever stolen and deadlines never fight.
	flipped := false
	hsStart := time.Now()
	if _, err := app.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var seq uint32
		buf := make([]byte, 1200)
		sent := 0
		for {
			app.SetDeadline(time.Now().Add(3 * time.Minute))
			n, err := app.Read(buf)
			if err != nil || n == 0 {
				return
			}
			off := 0
			for off < n {
				total := pickClassLatency(udpClasses, sent)
				budget := total - 25 - 16
				end := off + budget - 2
				if end > n {
					end = n
				}
				ks.Lock()
				aead, early := ks.aead, ks.early
				ks.Unlock()
				var fl byte
				if early {
					fl = 2
				}
				dg := sealDgramFast(aead, sid, fl, seq, buf[off:end], total)
				seq++
				sent += end - off
				us.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, err := us.Write(dg); err != nil {
					return
				}
				off = end
			}
		}
	}()
	expect := uint32(0)
	pending := map[uint32][]byte{}
	var gapSince time.Time
	rbuf := make([]byte, 2048)
	for {
		select {
		case <-done:
			return
		default:
		}
		us.SetReadDeadline(time.Now().Add(helloRetryInterval))
		n, err := us.Read(rbuf)
		if err != nil {
			if !flipped {
				if time.Since(hsStart) > helloTimeout {
					return
				}
				us.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_, _ = us.Write(hello)
				continue
			}
			continue
		}
		dg := rbuf[:n]
		if !validClass(udpClasses, len(dg)) || string(dg[:8]) != string(sid) {
			continue
		}
		if !flipped {
			// try hello reply first
			if len(dg) >= 56 {
				ephS := dg[8:40]
				m2 := hmac.New(sha256.New, psk)
				m2.Write([]byte{version})
				m2.Write(ephS)
				m2.Write(ephPub)
				m2.Write(hsNonce)
				m2.Write(sid)
				if hmac.Equal(m2.Sum(nil)[:16], dg[40:56]) {
					shared, err := curve25519.X25519(ephPriv, ephS)
					if err != nil {
						return
					}
					fsAead, _ := chacha20poly1305.New(fsKey(psk, shared))
					ks.Lock()
					ks.aead = fsAead
					ks.early = false
					ks.Unlock()
					flipped = true
					continue
				}
			}
		}
		ks.Lock()
		aead := ks.aead
		ks.Unlock()
		pt, err := aead.Open(nil, dg[8:20], dg[25:], append(append(append([]byte(nil), dg[:8]...), dg[20]), dg[21:25]...))
		if err != nil {
			// replies race the key flip on fast paths; sk0 is equally
			// authenticated, so always try it as fallback.
			pt, err = a0.Open(nil, dg[8:20], dg[25:], append(append(append([]byte(nil), dg[:8]...), dg[20]), dg[21:25]...))
		}
		if err != nil {
			continue
		}
		seq := binary.BigEndian.Uint32(dg[21:25])
		ln := int(binary.BigEndian.Uint16(pt[:2]))
		budget := len(dg) - 25 - 16
		if ln < 0 || 2+ln > budget || 2+ln > len(pt) {
			continue
		}
		data := append([]byte(nil), pt[2:2+ln]...)
		if seq < expect {
			continue
		}
		if _, dup := pending[seq]; !dup && len(pending) < 64 {
			pending[seq] = data
		}
		drained := false
		for {
			d, ok := pending[expect]
			if !ok {
				break
			}
			delete(pending, expect)
			app.SetDeadline(time.Now().Add(3 * time.Minute))
			if _, err := app.Write(d); err != nil {
				return
			}
			expect++
			drained = true
		}
		if drained {
			gapSince = time.Time{}
		} else if len(pending) > 0 {
			if gapSince.IsZero() {
				gapSince = time.Now()
			} else if time.Since(gapSince) > udpGapFast {
				min := seq
				for k := range pending {
					if k < min {
						min = k
					}
				}
				expect = min
				gapSince = time.Time{}
			}
		}
	}
}

// raceLegs runs TCP and UDP handshakes concurrently; first verified win.
func raceLegs(server string, port int, psk []byte, atyp byte, addr, portb []byte) *established {
	type result struct {
		es  *established
		err error
	}
	tcpCh := make(chan result, 1)
	udpCh := make(chan result, 1)
	go func() {
		es, err := handshakeTCP(server, port, psk, atyp, addr, portb)
		tcpCh <- result{es, err}
	}()
	go func() {
		es, err := handshakeUDP(server, port, psk, atyp, addr, portb)
		udpCh <- result{es, err}
	}()
	timeout := time.After(12 * time.Second)
	var tcpRes, udpRes *result
	for tcpRes == nil || udpRes == nil {
		select {
		case r := <-tcpCh:
			tcpRes = &r
			if r.err == nil {
				setPinned("tcp")
				go func() {
					u := <-udpCh
					if u.err == nil && u.es != nil {
						u.es.us.Close()
					}
					udpRes = &u
				}()
				return r.es
			}
		case r := <-udpCh:
			udpRes = &r
			if r.err == nil {
				setPinned("udp")
				go func() {
					t := <-tcpCh
					if t.err == nil && t.es != nil {
						t.es.up.Close()
					}
					tcpRes = &t
				}()
				return r.es
			}
		case <-timeout:
			if tcpRes != nil && tcpRes.err == nil {
				return tcpRes.es
			}
			if udpRes != nil && udpRes.err == nil {
				return udpRes.es
			}
			return nil
		}
	}
	if tcpRes != nil && tcpRes.err == nil {
		return tcpRes.es
	}
	if udpRes != nil && udpRes.err == nil {
		return udpRes.es
	}
	return nil
}

// ---------- SOCKS front ----------

func readN(c net.Conn, n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(c, b)
	return b, err
}

func handle(app net.Conn, server string, port int, psk []byte, transport string) {
	defer app.Close()
	ver, err := readN(app, 1)
	if err != nil || ver[0] != 5 {
		return
	}
	nm, err := readN(app, 1)
	if err != nil {
		return
	}
	methods, err := readN(app, int(nm[0]))
	if err != nil {
		return
	}
	ok := false
	for _, m := range methods {
		if m == 0 {
			ok = true
		}
	}
	if !ok {
		app.Write([]byte{5, 0xff})
		return
	}
	if _, err := app.Write([]byte{5, 0}); err != nil {
		return
	}
	hdr, err := readN(app, 4)
	if err != nil || hdr[0] != 5 || hdr[1] != 1 {
		return
	}
	atyp := hdr[3]
	var addr []byte
	switch atyp {
	case 1:
		addr, err = readN(app, 4)
	case 3:
		var l []byte
		l, err = readN(app, 1)
		if err != nil {
			return
		}
		var name []byte
		name, err = readN(app, int(l[0]))
		if err != nil {
			return
		}
		addr = append([]byte{l[0]}, name...)
	case 4:
		addr, err = readN(app, 16)
	default:
		return
	}
	if err != nil {
		return
	}
	portb, err := readN(app, 2)
	if err != nil {
		return
	}
	switch transport {
	case "tcp":
		// Early SOCKS reply inside handshake overlaps browser TLS with Specter RTT.
		es, err := handshakeTCPEarly(app, server, port, psk, atyp, addr, portb)
		if err != nil {
			return
		}
		relayTCP(app, es)
	case "udp":
		udpLegPinned(app, server, port, psk, atyp, addr, portb)
	default: // auto: pinned fast path, else race; early reply overlaps RTT
		if pin := getPinned(); pin == "tcp" {
			if es, err := handshakeTCPEarly(app, server, port, psk, atyp, addr, portb); err == nil {
				relayTCP(app, es)
				return
			}
		} else if pin == "udp" {
			udpLegPinned(app, server, port, psk, atyp, addr, portb)
			return
		}
		// No pin yet (or pinned failed): optimistic early reply, then race.
		// Browser pipelines ClientHello while race is in flight (kernel-buffered).
		tuneTCP(app)
		app.SetDeadline(time.Now().Add(3 * time.Minute))
		if _, err := app.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		// Prevent double SOCKS reply: race winners must not write again.
		// Temporarily wrap app so relay sees it as already-replied.
		es := raceLegs(server, port, psk, atyp, addr, portb)
		if es == nil {
			return
		}
		if es.transport == "tcp" {
			relayTCPNoReply(app, es)
		} else {
			relayUDP(app, es)
		}
	}
}

// relayTCPNoReply is relayTCP when SOCKS success was already sent early
// (auto pinned-race path). Avoids writing the 10B reply twice.
func relayTCPNoReply(app net.Conn, e *established) {
	relayTCP(app, e)
}

func main() {
	server, port, psk, transport := loadConfig()
	ln, err := net.Listen("tcp", socksListen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("specter-go v3.2 client [%s] socks5 %s -> %s:%d", transport, socksListen, server, port)
	_ = psk
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c, server, port, psk, transport)
	}
}
