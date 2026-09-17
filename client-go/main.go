package main

// Specter client (Go): SOCKS5 on 127.0.0.1:10867 -> Specter AEAD protocol.
// Config: config.json (server/port/psk/transport tcp|udp|auto) or argv path.
// Env overrides: SPECTER_SERVER/PORT/PSK/TRANSPORT.

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	version     = 0x03 // wire protocol version (NOT the app release)
	muxVersion  = 0x04 // same wire, muxed streams (needs server muxOn)
	socksListen = "127.0.0.1:10867"
)

// errMuxUnsupported signals a silent-close on a 0x04 handshake: the server
// speaks legacy-only (old binary or SPECTER_MUX=off). Auto mode falls back
// to a 0x03 handshake; mux=on fails closed.
var errMuxUnsupported = errors.New("mux unsupported by server")

// appVersion is the release version. Bump this one place on release;
// the wire version above only changes on protocol breaks.
const appVersion = "v3.5.0"

var tcpClasses = []int{320, 576, 1024, 1420}
var udpClasses = []int{576, 1024, 1280}

// Datagram flag bits (mirror server). 0x04 advertises ACK support;
// 0x08 marks server ACK datagrams (never sent by old servers).
const (
	udpFlagHello  = 0x01
	udpFlagEarly  = 0x02
	udpFlagAckCap = 0x04
	udpFlagAck    = 0x08
)

// First-flight retransmit: how many leading datagrams we keep copies of,
// resend interval, and give-up age (then inner TCP retransmits if needed).
const (
	flightTrackMax   = 16
	flightResendEvery = 250 * time.Millisecond
	flightGiveUpAfter = 3 * time.Second
)

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

// --- logging (SPECTER_LOG=error|warn|info|debug, default warn) ---
const (
	logError = 0
	logWarn  = 1
	logInfo  = 2
	logDebug = 3
)

var logLevel = func() int {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SPECTER_LOG"))) {
	case "debug":
		return logDebug
	case "info":
		return logInfo
	case "error":
		return logError
	default:
		return logWarn
	}
}()

func logf(level int, format string, args ...interface{}) {
	if level <= logLevel {
		log.Printf(format, args...)
	}
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
	Mux       string `json:"mux"` // on | off | auto (default auto)
}

func loadConfig() (server string, port int, psk []byte, transport, muxMode string) {
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
	if v := os.Getenv("SPECTER_MUX"); v != "" {
		cfg.Mux = v
	}
	if cfg.Mux == "" {
		cfg.Mux = "auto"
	}
	if cfg.Mux != "on" && cfg.Mux != "off" && cfg.Mux != "auto" {
		log.Fatal(`mux must be "on", "off" or "auto"`)
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
					Mux:       "auto",
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
	return cfg.Server, cfg.Port, b, cfg.Transport, cfg.Mux
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

// ---------- mux frames (0x04 TCP sessions, one frame per record) ----------
const (
	muxFrameHdr = 7
	muxSYN      = 0x01 // client->server open, data = target atyp+addr+port
	muxDATA     = 0x02
	muxFIN      = 0x04
	muxRST      = 0x08
	muxSYNACK   = 0x10 // server->client open-ok
	muxSYNFAIL  = 0x20 // server->client open-failed
	muxPING     = 0x40 // trunk control (sid 0), data = 8B nanotime
	muxPONG     = 0x80 // trunk control (sid 0), echoes PING payload

	muxMaxStreams = 1024 // local cap; server enforces its own 256
	muxBufCap     = 8 << 20

	// Per-stream credit flow control, mirroring the server: senders
	// start with muxInitWin and every receiver grants muxWinQuantum
	// per 64KB consumed. Unlimited until the first WIN arrives, so old
	// peers behave exactly as before.
	muxInitWin    = 1 << 20
	muxWinQuantum = 64 << 10

	// Trunk keepalive: PING when idle this long (beats NAT timeouts);
	// RTT summary logged every muxSummaryEvery.
	muxKeepaliveEvery = 25 * time.Second
	muxSummaryEvery   = 60 * time.Second
)

func muxEncode(sid uint32, flags byte, data []byte) []byte {
	f := make([]byte, muxFrameHdr+len(data))
	binary.BigEndian.PutUint32(f[0:4], sid)
	f[4] = flags
	binary.BigEndian.PutUint16(f[5:7], uint16(len(data)))
	copy(f[7:], data)
	return f
}

func muxDecode(frame []byte) (sid uint32, flags byte, data []byte, ok bool) {
	if len(frame) < muxFrameHdr {
		return 0, 0, nil, false
	}
	ln := int(binary.BigEndian.Uint16(frame[5:7]))
	if ln < 0 || muxFrameHdr+ln != len(frame) {
		return 0, 0, nil, false
	}
	return binary.BigEndian.Uint32(frame[0:4]), frame[4], frame[7 : 7+ln], true
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
		return
	}
	_ = c.Close()
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

// handshakeTCP performs hs + optional first record (target, sk0) in one
// flight, verifies the reply, and returns a live session. ver selects the
// wire mode (0x03 legacy single-stream, 0x04 mux trunk); tgt==nil sends the
// handshake alone (mux trunk creation, streams open later).
func handshakeTCP(server string, port int, psk []byte, ver byte, tgt []byte) (*established, error) {
	magic := randBytes(4)
	nonce := randBytes(16)
	ephPriv, ephPub := genEphemeral()
	m := hmac.New(sha256.New, psk)
	m.Write([]byte{ver})
	m.Write(magic)
	m.Write(nonce)
	m.Write(ephPub)
	tag := m.Sum(nil)[:16]
	sk0 := hsKey(psk, nonce)
	up, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", server, port), 10*time.Second)
	if err != nil {
		logf(logWarn, "tcp dial fail %s:%d err=%v (server down/firewalled?)", server, port, err)
		return nil, err
	}
	tuneTCP(up)
	hs := make([]byte, 0, 69)
	hs = append(hs, ver)
	hs = append(hs, magic...)
	hs = append(hs, nonce...)
	hs = append(hs, ephPub...)
	hs = append(hs, tag...)
	flight := hs
	if tgt != nil {
		// latency: smallest class for target (usually <100B) avoids 1KB pad on handshake
		flight = append(hs, sealRecord(sk0, tgt, tcpClasses[0])...)
	}
	up.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := up.Write(flight); err != nil {
		up.Close()
		return nil, err
	}
	rep := make([]byte, 49)
	if _, err := io.ReadFull(up, rep); err != nil {
		up.Close()
		// Silent close before/at reply on a 0x04 handshake means the
		// server speaks legacy-only (old binary or mux disabled).
		if ver == muxVersion {
			return nil, fmt.Errorf("mux handshake %s:%d: %w", server, port, errMuxUnsupported)
		}
		logf(logWarn, "tcp no server reply %s:%d err=%v (wrong PSK/port? server overloaded?)", server, port, err)
		return nil, err
	}
	if rep[0] != ver {
		up.Close()
		if ver == muxVersion {
			return nil, fmt.Errorf("mux handshake %s:%d: bad version: %w", server, port, errMuxUnsupported)
		}
		logf(logError, "tcp bad version from %s:%d (incompatible server?)", server, port)
		return nil, fmt.Errorf("bad version")
	}
	ephS := rep[1:33]
	m2 := hmac.New(sha256.New, psk)
	m2.Write([]byte{ver})
	m2.Write(ephS)
	m2.Write(ephPub)
	m2.Write(nonce)
	if !hmac.Equal(m2.Sum(nil)[:16], rep[33:49]) {
		up.Close()
		logf(logError, "tcp reply tag mismatch %s:%d (wrong PSK?)", server, port)
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

// handshakeTCPEarly overlaps browser I/O with Specter RTT: it dials+sends the
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
		logf(logWarn, "tcp dial fail %s:%d err=%v (server down/firewalled?)", server, port, err)
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
		logf(logWarn, "tcp no server reply %s:%d err=%v (wrong PSK/port? server overloaded?)", server, port, err)
		up.Close()
		return nil, err
	}
	if rep[0] != version {
		up.Close()
		logf(logError, "tcp bad version from %s:%d (incompatible server?)", server, port)
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
		logf(logError, "tcp reply tag mismatch %s:%d (wrong PSK?)", server, port)
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
				logf(logDebug, "tcp relay server->app end err=%v", err)
				return
			}
			e.up.SetDeadline(time.Now().Add(3 * time.Minute))
			app.SetDeadline(time.Now().Add(3 * time.Minute))
			if _, err := app.Write(d); err != nil {
				logf(logDebug, "tcp relay app write end err=%v", err)
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
				logf(logDebug, "tcp relay app->server end err=%v", err)
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

// flightTracker keeps copies of the first flightTrackMax datagrams of a
// UDP connection and resends the unacked ones until the server's selective
// ACKs cover them (or they age out). Resends are bit-identical duplicates
// (same nonce+plaintext), so they are cryptographically safe and the
// server dedups them by sequence number.
type flightTracker struct {
	mu    sync.Mutex
	pkts  map[uint32]trackedPkt
	start time.Time
}

type trackedPkt struct {
	dg   []byte
	last time.Time
}

func newFlightTracker() *flightTracker {
	return &flightTracker{pkts: map[uint32]trackedPkt{}, start: time.Now()}
}

func (f *flightTracker) track(seq uint32, dg []byte) {
	if seq >= flightTrackMax {
		return
	}
	f.mu.Lock()
	if len(f.pkts) < flightTrackMax {
		f.pkts[seq] = trackedPkt{dg: dg, last: time.Now()}
	}
	f.mu.Unlock()
}

// onAck marks everything cumulatively acked plus SACK bits as received.
func (f *flightTracker) onAck(cumul uint32, mask uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for seq := range f.pkts {
		if cumul-seq < 1<<31 {
			delete(f.pkts, seq)
			continue
		}
		if d := seq - (cumul + 1); d < 32 && mask&(1<<d) != 0 {
			delete(f.pkts, seq)
		}
	}
}

// due returns copies needing resend: unacked, due interval elapsed, young.
func (f *flightTracker) due(now time.Time) [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]byte
	for seq, tp := range f.pkts {
		if now.Sub(f.start) > flightGiveUpAfter {
			delete(f.pkts, seq)
			continue
		}
		if now.Sub(tp.last) >= flightResendEvery {
			tp.last = now
			f.pkts[seq] = tp
			out = append(out, tp.dg)
		}
	}
	return out
}

func (f *flightTracker) empty() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pkts) == 0
}

// retransmitLoop resends unacked first-flight datagrams until done closes
// (connection end) or everything is acked/expired.
func retransmitLoop(us net.Conn, f *flightTracker, done <-chan struct{}) {
	t := time.NewTicker(flightResendEvery)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case now := <-t.C:
			for _, dg := range f.due(now) {
				us.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, err := us.Write(dg); err != nil {
					return
				}
			}
			if f.empty() && time.Since(f.start) > flightGiveUpAfter {
				return
			}
		}
	}
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
	fad = append(fad, udpFlagHello|udpFlagAckCap)
	fad = append(fad, 0, 0, 0, 0)
	fct := a.Seal(nil, hsNonce[:12], hpt, fad)
	hello := make([]byte, 0, helloTotal)
	hello = append(hello, version)
	hello = append(hello, magic...)
	hello = append(hello, hsNonce...)
	hello = append(hello, ephPub...)
	hello = append(hello, tag...)
	hello = append(hello, sid...)
	hello = append(hello, 0, 0, 0, 0, udpFlagHello|udpFlagAckCap)
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
				logf(logWarn, "udp no hello reply %s:%d (server down? UDP blocked? wrong PSK?)", server, port)
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
	flight := newFlightTracker()
	go retransmitLoop(e.us, flight, done)
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
				dg := sealDgramFast(aead, sid, udpFlagAckCap, seq, buf[off:end], total)
				flight.track(seq, dg)
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
			logf(logDebug, "udp relay end err=%v", err)
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
		if dg[20]&udpFlagAck != 0 {
			// Server selective ACK, not stream data.
			if len(pt) >= 10 {
				flight.onAck(binary.BigEndian.Uint32(pt[2:6]), binary.BigEndian.Uint32(pt[6:10]))
			}
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
	fad := append(append(append([]byte(nil), sid...), udpFlagHello|udpFlagAckCap), 0, 0, 0, 0)
	fct := a0.Seal(nil, hsNonce[:12], hpt, fad)
	hello := make([]byte, 0, total)
	hello = append(hello, version)
	hello = append(hello, magic...)
	hello = append(hello, hsNonce...)
	hello = append(hello, ephPub...)
	hello = append(hello, tag...)
	hello = append(hello, sid...)
	hello = append(hello, 0, 0, 0, 0, udpFlagHello|udpFlagAckCap)
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
	flight := newFlightTracker()
	go retransmitLoop(us, flight, done)
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
					fl = udpFlagEarly
				}
				fl |= udpFlagAckCap
				dg := sealDgramFast(aead, sid, fl, seq, buf[off:end], total)
				flight.track(seq, dg)
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
					logf(logWarn, "udp hello timeout %s:%d (server down? UDP blocked? wrong PSK?)", server, port)
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
		if dg[20]&udpFlagAck != 0 {
			// Server selective ACK, not stream data.
			if len(pt) >= 10 {
				flight.onAck(binary.BigEndian.Uint32(pt[2:6]), binary.BigEndian.Uint32(pt[6:10]))
			}
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
		tgt := append([]byte{atyp}, addr...)
		tgt = append(tgt, portb...)
		es, err := handshakeTCP(server, port, psk, version, tgt)
		tcpCh <- result{es, err}
	}()
	go func() {
		es, err := handshakeUDP(server, port, psk, atyp, addr, portb)
		udpCh <- result{es, err}
	}()
	timeout := time.After(12 * time.Second)
	var tcpRes, udpRes *result
	var tcpE, udpE error
	for tcpRes == nil || udpRes == nil {
		select {
		case r := <-tcpCh:
			tcpRes = &r
			tcpE = r.err
			if r.err == nil {
				setPinned("tcp")
				// Reap the loser: its result channel is buffered (cap 1)
				// so its handshake always completes without blocking;
				// closing here just fails it fast. This goroutine touches
				// no shared state — tcpRes/udpRes stay outer-only.
				go func() {
					if u := <-udpCh; u.err == nil && u.es != nil {
						u.es.us.Close()
					}
				}()
				return r.es
			}
		case r := <-udpCh:
			udpRes = &r
			udpE = r.err
			if r.err == nil {
				setPinned("udp")
				go func() {
					if t := <-tcpCh; t.err == nil && t.es != nil {
						t.es.up.Close()
					}
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
			logf(logWarn, "race: both transports failed %s:%d (tcp=%v udp=%v)", server, port, tcpE, udpE)
			return nil
		}
	}
	if tcpRes != nil && tcpRes.err == nil {
		return tcpRes.es
	}
	if udpRes != nil && udpRes.err == nil {
		return udpRes.es
	}
	logf(logWarn, "race: both transports failed %s:%d (tcp=%v udp=%v)", server, port, tcpE, udpE)
	return nil
}

// ---------- mux trunk (0x04 TCP sessions, client side) ----------

type muxStream struct {
	id      uint32
	app     net.Conn
	q       chan []byte // trunk -> app payloads; nil chunk = FIN
	dead    chan struct{}
	done    chan struct{} // closed when the stream fully tore down
	sendWin int64         // remaining send credit (atomic; gated by gotWin)
	gotWin  atomic.Bool   // server sent a WIN: flow control engaged
}

type muxTrunk struct {
	key      string
	conn     net.Conn
	aead     cipher.AEAD
	mu       sync.Mutex
	streams  map[uint32]*muxStream
	nextID   uint32
	dead     bool
	wmu      sync.Mutex
	sent     int
	buffered int64
	lastSend atomic.Int64 // unixnano of last frame sent (keepalive)
	rttMu    sync.Mutex
	rttEMA   time.Duration
	rttMin   time.Duration
	rttLast  time.Duration
	rttN     uint64
	rttAt    time.Time
}

// waitWindow blocks until n bytes of send credit exist. See server twin.
func waitWindow(win *int64, gotWin *atomic.Bool, n int, dead <-chan struct{}) bool {
	if !gotWin.Load() {
		return true
	}
	for {
		if atomic.LoadInt64(win) >= int64(n) {
			return true
		}
		select {
		case <-dead:
			return false
		case <-time.After(2 * time.Millisecond):
		}
	}
}

// winSid builds a WINDOW_UPDATE payload crediting one quantum to sid.
func winSid(sid uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], sid)
	return b[:]
}

var trunkMu sync.Mutex
var trunks = map[string]*muxTrunk{}

type muxCapEntry struct {
	ok  bool
	exp time.Time
}

var muxCapMu sync.Mutex
var muxCapCache = map[string]muxCapEntry{}
const muxCapTTL = 5 * time.Minute

func muxServerKey(server string, port int) string {
	return fmt.Sprintf("%s:%d", server, port)
}

func getMuxCap(key string) (ok, fresh bool) {
	muxCapMu.Lock()
	defer muxCapMu.Unlock()
	e, hit := muxCapCache[key]
	if !hit || time.Now().After(e.exp) {
		return false, false
	}
	return e.ok, true
}

func setMuxCap(key string, ok bool) {
	muxCapMu.Lock()
	muxCapCache[key] = muxCapEntry{ok: ok, exp: time.Now().Add(muxCapTTL)}
	muxCapMu.Unlock()
}

// ensureMuxTrunk returns the shared trunk for server:port, dialing a 0x04
// handshake if needed. Concurrent callers share the winner; the loser closes
// its fresh conn. errMuxUnsupported (wrapped) when the server speaks legacy.
func ensureMuxTrunk(server string, port int, psk []byte) (*muxTrunk, error) {
	key := muxServerKey(server, port)
	trunkMu.Lock()
	if t, ok := trunks[key]; ok && !t.isDead() {
		trunkMu.Unlock()
		return t, nil
	}
	trunkMu.Unlock()
	if ok, fresh := getMuxCap(key); fresh && !ok {
		return nil, fmt.Errorf("mux %s: %w", key, errMuxUnsupported)
	}
	es, err := handshakeTCP(server, port, psk, muxVersion, nil)
	if err != nil {
		if errors.Is(err, errMuxUnsupported) {
			setMuxCap(key, false)
		}
		return nil, err
	}
	aead, _ := chacha20poly1305.New(es.sk)
	t := &muxTrunk{key: key, conn: es.up, aead: aead, streams: map[uint32]*muxStream{}, nextID: 1}
	trunkMu.Lock()
	if cur, ok := trunks[key]; ok && !cur.isDead() {
		trunkMu.Unlock()
		es.up.Close()
		return cur, nil
	}
	trunks[key] = t
	trunkMu.Unlock()
	t.lastSend.Store(time.Now().UnixNano())
	go t.readLoop()
	go t.keepaliveLoop()
	return t, nil
}

func (t *muxTrunk) isDead() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dead
}

func (t *muxTrunk) sendFrame(sid uint32, flags byte, data []byte) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	total := pickClassLatency(tcpClasses, t.sent)
	t.sent += len(data)
	t.lastSend.Store(time.Now().UnixNano())
	_, err := t.conn.Write(sealRecordFast(t.aead, muxEncode(sid, flags, data), total))
	return err
}

func (t *muxTrunk) writeData(sid uint32, data []byte) error {
	for len(data) > 0 {
		t.wmu.Lock()
		total := pickClassLatency(tcpClasses, t.sent)
		n := total - 2 - 12 - 16 - 2 - muxFrameHdr
		if n > len(data) {
			n = len(data)
		}
		rec := sealRecordFast(t.aead, muxEncode(sid, muxDATA, data[:n]), total)
		t.sent += n
		t.lastSend.Store(time.Now().UnixNano())
		_, err := t.conn.Write(rec)
		t.wmu.Unlock()
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func (t *muxTrunk) killStream(id uint32) {
	t.mu.Lock()
	st, ok := t.streams[id]
	if ok {
		delete(t.streams, id)
	}
	t.mu.Unlock()
	if ok {
		close(st.dead)
		st.app.Close()
		close(st.done)
	}
}

// openStream SYNs a stream and pumps until it ends (mirrors relayTCP's
// blocking contract so handle's deferred app.Close runs at the right time).
// The caller writes the SOCKS reply after nil error.
func (t *muxTrunk) openStream(app net.Conn, atyp byte, addr, portb []byte) error {
	t.mu.Lock()
	if t.dead {
		t.mu.Unlock()
		return fmt.Errorf("trunk dead")
	}
	if len(t.streams) >= muxMaxStreams {
		t.mu.Unlock()
		return fmt.Errorf("too many streams")
	}
	id := t.nextID
	t.nextID++
	if t.nextID == 0 {
		t.nextID = 1 // wrap guard; live streams hold old IDs briefly
	}
	st := &muxStream{id: id, app: app, q: make(chan []byte, 256), dead: make(chan struct{}), done: make(chan struct{}), sendWin: muxInitWin}
	t.streams[id] = st
	t.mu.Unlock()
	tgt := append([]byte{atyp}, addr...)
	tgt = append(tgt, portb...)
	if err := t.sendFrame(id, muxSYN, tgt); err != nil {
		t.killStream(id)
		<-st.done
		return err
	}
	finisher := make(chan struct{}, 2)
	go func() { // app -> trunk
		defer func() { finisher <- struct{}{} }()
		buf := make([]byte, 1388)
		for {
			app.SetDeadline(time.Now().Add(3 * time.Minute))
			n, err := app.Read(buf)
			if n > 0 {
				if !waitWindow(&st.sendWin, &st.gotWin, n, st.dead) {
					return
				}
				if werr := t.writeData(id, buf[:n]); werr != nil {
					_ = t.sendFrame(id, muxRST, nil)
					return
				}
				atomic.AddInt64(&st.sendWin, -int64(n))
			}
			if err != nil {
				if err == io.EOF {
					_ = t.sendFrame(id, muxFIN, nil)
				} else {
					_ = t.sendFrame(id, muxRST, nil)
				}
				return
			}
		}
	}()
	go func() { // trunk -> app
		defer func() { finisher <- struct{}{} }()
		winAcc := 0
		for {
			select {
			case chunk := <-st.q:
				if chunk == nil {
					closeWrite(app)
					return
				}
				atomic.AddInt64(&t.buffered, -int64(len(chunk)))
				app.SetDeadline(time.Now().Add(3 * time.Minute))
				if _, err := app.Write(chunk); err != nil {
					return
				}
				winAcc += len(chunk)
				if winAcc >= muxWinQuantum {
					winAcc -= muxWinQuantum
					_ = t.sendFrame(0, 0, winSid(id))
				}
			case <-st.dead:
				return
			}
		}
	}()
	go func() { // reaper
		<-finisher
		<-finisher
		t.killStream(id)
	}()
	<-st.done
	return nil
}

func (t *muxTrunk) enqueue(sid uint32, chunk []byte) {
	t.mu.Lock()
	st, known := t.streams[sid]
	t.mu.Unlock()
	if !known {
		return
	}
	if chunk == nil {
		select {
		case st.q <- nil:
		case <-st.dead:
		}
		return
	}
	atomic.AddInt64(&t.buffered, int64(len(chunk)))
	select {
	case st.q <- chunk:
	case <-st.dead:
		atomic.AddInt64(&t.buffered, -int64(len(chunk)))
	}
}

// creditWin applies one quantum of send credit from a WINDOW_UPDATE.
func (t *muxTrunk) creditWin(sid uint32) {
	t.mu.Lock()
	st, ok := t.streams[sid]
	t.mu.Unlock()
	if ok {
		st.gotWin.Store(true)
		atomic.AddInt64(&st.sendWin, muxWinQuantum)
	}
}

// fmtRTT renders sub-ms RTTs in micros so loopback/dev numbers stay useful.
func fmtRTT(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	return d.Round(time.Millisecond).String()
}

// sampleRTT folds a PONG measurement into the trunk stats.
func (t *muxTrunk) sampleRTT(rtt time.Duration) {
	t.rttMu.Lock()
	defer t.rttMu.Unlock()
	if t.rttN == 0 || rtt < t.rttMin {
		t.rttMin = rtt
	}
	if t.rttN == 0 {
		t.rttEMA = rtt
	} else {
		t.rttEMA = t.rttEMA*4/5 + rtt/5
	}
	t.rttLast = rtt
	t.rttN++
	t.rttAt = time.Now()
	logf(logDebug, "mux trunk %s rtt=%s", t.key, fmtRTT(rtt))
}

// keepaliveLoop PINGs idle trunks (NAT survival) and logs an RTT summary.
func (t *muxTrunk) keepaliveLoop() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	lastSummary := time.Now()
	for {
		select {
		case <-tick.C:
			if t.isDead() {
				return
			}
			now := time.Now()
			if now.Sub(time.Unix(0, t.lastSend.Load())) > muxKeepaliveEvery {
				var ts [8]byte
				binary.BigEndian.PutUint64(ts[:], uint64(now.UnixNano()))
				_ = t.sendFrame(0, muxPING, ts[:])
			}
			if now.Sub(lastSummary) >= muxSummaryEvery {
				lastSummary = now
				t.rttMu.Lock()
				n, ema, min, last := t.rttN, t.rttEMA, t.rttMin, t.rttLast
				t.rttMu.Unlock()
				if n > 0 {
					logf(logInfo, "mux trunk %s rtt last=%s ema=%s min=%s samples=%d", t.key, fmtRTT(last), fmtRTT(ema), fmtRTT(min), n)
				}
			}
		}
	}
}

func (t *muxTrunk) readLoop() {
	defer t.kill()
	for {
		for atomic.LoadInt64(&t.buffered) > muxBufCap {
			time.Sleep(5 * time.Millisecond)
		}
		t.conn.SetDeadline(time.Now().Add(3 * time.Minute))
		d, err := readRecordFast(t.conn, t.aead)
		if err != nil {
			logf(logDebug, "mux trunk read end err=%v", err)
			return
		}
		sid, flags, data, ok := muxDecode(d)
		if !ok {
			logf(logDebug, "mux bad frame")
			continue
		}
		if sid == 0 {
			// Trunk control, never a stream.
			switch {
			case flags&muxPONG != 0 && len(data) == 8:
				sent := int64(binary.BigEndian.Uint64(data))
				if rtt := time.Now().UnixNano() - sent; rtt > 0 && rtt < int64(time.Minute) {
					t.sampleRTT(time.Duration(rtt))
				}
			case flags&muxPING != 0 && len(data) == 8:
				_ = t.sendFrame(0, muxPONG, append([]byte(nil), data...))
			case flags == 0 && len(data) == 4:
				t.creditWin(binary.BigEndian.Uint32(data))
			default:
				logf(logDebug, "mux control ignored flags=%02x", flags)
			}
			continue
		}
		switch {
		case flags&muxSYNFAIL != 0 || flags&muxRST != 0:
			t.killStream(sid)
		case flags&muxFIN != 0:
			if len(data) > 0 {
				t.enqueue(sid, data)
			}
			t.enqueue(sid, nil)
		default:
			t.enqueue(sid, data)
		}
	}
}

// kill resets the trunk: streams die (app conns close, browsers retry and
// retrunk on demand) and the manager forgets it.
func (t *muxTrunk) kill() {
	t.mu.Lock()
	if t.dead {
		t.mu.Unlock()
		return
	}
	t.dead = true
	ids := make([]uint32, 0, len(t.streams))
	for id := range t.streams {
		ids = append(ids, id)
	}
	t.mu.Unlock()
	for _, id := range ids {
		t.killStream(id)
	}
	trunkMu.Lock()
	if cur, ok := trunks[t.key]; ok && cur == t {
		delete(trunks, t.key)
	}
	trunkMu.Unlock()
	t.conn.Close()
	if len(ids) > 0 {
		t.rttMu.Lock()
		last := t.rttLast
		t.rttMu.Unlock()
		if last > 0 {
			logf(logWarn, "mux trunk dead, reset %d streams (last rtt=%s)", len(ids), fmtRTT(last))
		} else {
			logf(logWarn, "mux trunk dead, reset %d streams", len(ids))
		}
	}
}

// ---------- SOCKS front ----------

func readN(c net.Conn, n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(c, b)
	return b, err
}

// socksTarget renders atyp+addr+portb as host:port for the access log.
func socksTarget(atyp byte, addr, portb []byte) string {
	port := 0
	if len(portb) == 2 {
		port = int(binary.BigEndian.Uint16(portb))
	}
	switch atyp {
	case 1:
		if len(addr) == 4 {
			return fmt.Sprintf("%s:%d", net.IP(addr).String(), port)
		}
	case 3:
		if len(addr) > 1 && int(addr[0]) == len(addr)-1 {
			return fmt.Sprintf("%s:%d", string(addr[1:]), port)
		}
	case 4:
		if len(addr) == 16 {
			return fmt.Sprintf("[%s]:%d", net.IP(addr).String(), port)
		}
	}
	return fmt.Sprintf("atyp=%d:%d", atyp, port)
}

func handle(app net.Conn, server string, port int, psk []byte, transport, muxMode string) {
	defer app.Close()
	ver, err := readN(app, 1)
	if err != nil || ver[0] != 5 {
		logf(logDebug, "socks reject: bad version err=%v", err)
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
		logf(logDebug, "socks reject: no no-auth method")
		app.Write([]byte{5, 0xff})
		return
	}
	if _, err := app.Write([]byte{5, 0}); err != nil {
		return
	}
	hdr, err := readN(app, 4)
	if err != nil || hdr[0] != 5 || hdr[1] != 1 {
		logf(logDebug, "socks reject: bad request err=%v", err)
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
	// Access log, always on (console): who asked for what.
	log.Printf("from %s accepted //%s [socks -> proxy]", app.RemoteAddr(), socksTarget(atyp, addr, portb))
	handleTransport(app, server, port, psk, transport, muxMode, atyp, addr, portb)
}

// socksSuccessReply is the 10-byte SOCKS5 connect-success. Written exactly
// once per connection, by exactly one of the paths below.
var socksSuccessReply = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}

// handleTransport picks mux trunk vs legacy single-stream:
//
//	mux=off                        -> legacy, exactly pre-mux behavior
//	mux=on + tcp leg               -> mux trunk, fail closed
//	mux=on + udp leg               -> refuse (mux needs a TCP leg)
//	mux=auto + tcp                 -> trunk, fallback to legacy on reject
//	mux=auto + udp                 -> legacy UDP (mux is TCP-only in v3.4)
//	mux=auto + auto                -> trunk attempt, fallback to leg race
func handleTransport(app net.Conn, server string, port int, psk []byte, transport, muxMode string, atyp byte, addr, portb []byte) {
	if muxMode == "off" {
		legacyHandle(app, server, port, psk, transport, atyp, addr, portb)
		return
	}
	if transport == "udp" {
		if muxMode == "on" {
			logf(logError, "mux=on needs a TCP leg, transport=udp configured; refusing (use mux=off/auto for UDP)")
			return
		}
		udpLegPinned(app, server, port, psk, atyp, addr, portb)
		return
	}
	if transport == "tcp" {
		if muxMode == "on" {
			t, err := ensureMuxTrunk(server, port, psk)
			if err != nil {
				logf(logError, "mux trunk fail: %v", err)
				return
			}
			if _, err := app.Write(socksSuccessReply); err != nil {
				return
			}
			t.openStream(app, atyp, addr, portb)
			return
		}
		if t, err := ensureMuxTrunk(server, port, psk); err == nil {
			if _, err := app.Write(socksSuccessReply); err != nil {
				return
			}
			t.openStream(app, atyp, addr, portb)
			return
		} else {
			logf(logDebug, "mux unavailable (%v), legacy TCP", err)
		}
		legacyHandle(app, server, port, psk, transport, atyp, addr, portb)
		return
	}
	// transport auto: trunk first (negative-cached on legacy servers so
	// this costs one dial only until the cache expires), else leg race.
	if t, err := ensureMuxTrunk(server, port, psk); err == nil {
		setPinned("tcp")
		if _, err := app.Write(socksSuccessReply); err != nil {
			return
		}
		t.openStream(app, atyp, addr, portb)
		return
	} else {
		logf(logDebug, "mux unavailable (%v), racing legs", err)
	}
	legacyHandle(app, server, port, psk, transport, atyp, addr, portb)
}

// legacyHandle is the pre-mux single-stream path (0x03 handshakes).
func legacyHandle(app net.Conn, server string, port int, psk []byte, transport string, atyp byte, addr, portb []byte) {
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
		// Neither race leg nor relay writes a second SOCKS reply.
		tuneTCP(app)
		app.SetDeadline(time.Now().Add(3 * time.Minute))
		if _, err := app.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		es := raceLegs(server, port, psk, atyp, addr, portb)
		if es == nil {
			return
		}
		// SOCKS success was already sent above; relay never writes it.
		if es.transport == "tcp" {
			relayTCP(app, es)
		} else {
			relayUDP(app, es)
		}
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	server, port, psk, transport, muxMode := loadConfig()
	ln, err := net.Listen("tcp", socksListen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("specter-go %s client [%s/mux=%s] socks5 %s -> %s:%d", appVersion, transport, muxMode, socksListen, server, port)
	_ = psk
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c, server, port, psk, transport, muxMode)
	}
}
