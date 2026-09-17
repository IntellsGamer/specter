package main

// Specter server: X25519 forward secrecy + HKDF session keys + AEAD cells.
// Env: SPECTER_PSK (64 hex, required, long-term salt/auth only).
//      SPECTER_LISTEN (default ":43117", TCP+UDP). SPECTER_TRANSPORT=tcp -> TCP only.
// NOT audited crypto.

import (
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"os"
	"strconv"
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
	muxVersion  = 0x04 // same wire, muxed streams (needs muxOn)
	maxConns    = 1024
	dialTO      = 10 * time.Second
	nonceTTL    = 10 * time.Minute
	udpIdle     = 120 * time.Second
	udpGap      = 100 * time.Millisecond

	udpMaxPayload = 1200

	// First N bytes per direction use smallest class (TTFB), then random.
	earlyBytesThreshold = 4096
	// First N bytes of UDP pump bypass pacing (interactive burst).
	pacerBypassBytes = 64 * 1024
	// DNS cache TTL for browsing fan-out to same domains.
	dnsCacheTTL = 60 * time.Second
)

// appVersion is the release version. Bump this one place on release;
// the wire version above only changes on protocol breaks.
const appVersion = "v3.4.0"

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

func pickClassLatency(classes []int, bytesSent int) int {
	if bytesSent < earlyBytesThreshold {
		return classes[0]
	}
	return pickClass(classes)
}

func tuneTCP(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

func validClass(classes []int, total int) bool {
	for _, c := range classes {
		if c == total {
			return true
		}
	}
	return false
}

// ---------- logging ----------
// SPECTER_LOG=error|warn|info|debug (default warn). Unauthenticated probe
// noise (scanners) is rate-limited at debug; anything that breaks a real
// (handshake-verified) session logs at warn. No keys or PSK material ever
// logged. Wire protocol untouched by all of this.
const (
	logError = 0
	logWarn  = 1
	logInfo  = 2
	logDebug = 3
)

var logLevel = parseLogLevel(os.Getenv("SPECTER_LOG"))

func parseLogLevel(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return logDebug
	case "info":
		return logInfo
	case "error":
		return logError
	default:
		return logWarn
	}
}

func logf(level int, format string, args ...interface{}) {
	if level <= logLevel {
		log.Printf(format, args...)
	}
}

// logRL is logf with per-category rate limiting for scanner-grade noise.
var rlMu sync.Mutex
var rlNext = map[string]time.Time{}
var rlSupp = map[string]int{}

func logRL(cat string, level int, every time.Duration, format string, args ...interface{}) {
	if level > logLevel {
		return
	}
	now := time.Now()
	rlMu.Lock()
	if next, ok := rlNext[cat]; ok && now.Before(next) {
		rlSupp[cat]++
		rlMu.Unlock()
		return
	}
	rlNext[cat] = now.Add(every)
	supp := rlSupp[cat]
	rlSupp[cat] = 0
	rlMu.Unlock()
	if supp > 0 {
		log.Printf("[%s] (+%d similar suppressed) "+format, append([]interface{}{supp}, args...)...)
		return
	}
	log.Printf("["+cat+"] "+format, args...)
}

// ---------- counters + periodic stats (SPECTER_LOG=info to see) ----------
var statsMu sync.Mutex
var stats = map[string]uint64{}

func statAdd(k string, n uint64) {
	statsMu.Lock()
	stats[k] += n
	statsMu.Unlock()
}

func statInc(k string) { statAdd(k, 1) }

var statsEvery = statsInterval()

func statsInterval() time.Duration {
	if v := os.Getenv("SPECTER_STATS_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 5 {
			return time.Duration(n) * time.Second
		}
	}
	return 5 * time.Minute
}

func statReport() {
	for range time.Tick(statsEvery) {
		statsMu.Lock()
		snapshot := make(map[string]uint64, len(stats))
		for k, v := range stats {
			snapshot[k] = v
		}
		statsMu.Unlock()
		logf(logInfo, "stats tcp_accept=%d(drop=%d) tcp_hs_ok=%d tcp_hs_reject=%d tcp_dial_fail=%d tcp_dial_slow=%d mux_dial_fail=%d mux_dial_slow=%d udp_hello_ok=%d udp_hello_reject=%d udp_dial_fail=%d udp_dial_slow=%d udp_done=%d orphan_drained=%d orphan_expired=%d",
			snapshot["tcp_accept"], snapshot["tcp_accept_drop"], snapshot["tcp_hs_ok"], snapshot["tcp_hs_reject"],
			snapshot["tcp_dial_fail"], snapshot["tcp_dial_slow"], snapshot["mux_dial_fail"], snapshot["mux_dial_slow"],
			snapshot["udp_hello_ok"],
			snapshot["udp_hello_reject"], snapshot["udp_dial_fail"], snapshot["udp_dial_slow"],
			snapshot["udp_done"], snapshot["orphan_drained"], snapshot["orphan_expired"])
	}
}

// dialTarget dials host:port with Happy-Eyeballs-style racing across all
// resolved addresses (250ms stagger, first success wins, overall dialTO).
// Failures and slow (>2s) dials log at warn — this is where user-visible
// -1s and spikes come from. kind is "tcp"/"udp" (the specter leg; the
// target dial itself is always TCP).
func dialTarget(kind, host, port string) (net.Conn, error) {
	start := time.Now()
	target := net.JoinHostPort(host, port)
	addrs := resolveHostList(host)
	var t net.Conn
	var err error
	if len(addrs) < 2 {
		t, err = net.DialTimeout("tcp", target, dialTO)
	} else {
		t, err = dialRace(addrs, port)
	}
	dt := time.Since(start)
	if err != nil {
		statInc(kind + "_dial_fail")
		logf(logWarn, "%s target dial fail target=%s addrs=%d err=%v", kind, target, len(addrs), err)
		return nil, err
	}
	if dt > 2*time.Second {
		statInc(kind + "_dial_slow")
		logf(logWarn, "%s target dial slow target=%s took=%s", kind, target, dt.Round(time.Millisecond))
	}
	return t, nil
}

// dialRace dials every address concurrently (RFC 8305-style 250ms stagger)
// and returns the first success. Losers are cancelled and closed; no
// goroutine or fd leaks: all sends land in the buffered channel, wg.Wait
// bounds the cleanup, and only the winner escapes.
func dialRace(addrs []string, port string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTO)
	defer cancel()
	type outcome struct {
		c   net.Conn
		err error
	}
	out := make(chan outcome, len(addrs))
	var wg sync.WaitGroup
	for i, a := range addrs {
		wg.Add(1)
		go func(i int, a string) {
			defer wg.Done()
			if i > 0 {
				t := time.NewTimer(time.Duration(i) * 250 * time.Millisecond)
				defer t.Stop()
				select {
				case <-ctx.Done():
					out <- outcome{err: ctx.Err()}
					return
				case <-t.C:
				}
			}
			d := net.Dialer{}
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(a, port))
			out <- outcome{c, err}
		}(i, a)
	}
	var firstErr error
	for range addrs {
		select {
		case o := <-out:
			if o.err == nil {
				cancel()
				wg.Wait()
				close(out)
				for o2 := range out {
					if o2.c != nil && o2.c != o.c {
						o2.c.Close()
					}
				}
				return o.c, nil
			}
			if firstErr == nil {
				firstErr = o.err
			}
		case <-ctx.Done():
			if firstErr == nil {
				firstErr = ctx.Err()
			}
			cancel()
			wg.Wait()
			return nil, firstErr
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("no addresses")
	}
	return nil, firstErr
}

// ---------- DNS cache (browsing opens many conns to same hosts) ----------
// Stores up to 4 addresses per host so dialTarget can race them.
var dnsCache = struct {
	sync.Mutex
	m map[string]cachedIPs
}{m: map[string]cachedIPs{}}

type cachedIPs struct {
	ips []string
	exp time.Time
}

const maxCachedIPs = 4

func resolveHostList(host string) []string {
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}
	}
	now := time.Now()
	dnsCache.Lock()
	if e, ok := dnsCache.m[host]; ok && now.Before(e.exp) {
		ips := e.ips
		dnsCache.Unlock()
		return ips
	}
	dnsCache.Unlock()
	// Resolve outside lock (may block). Never pass nil ctx here: net's
	// lookup path dereferences it and panics (crashed v3.2.0 on domains).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return []string{host} // fallback: let the dialer report the error
	}
	ips := make([]string, 0, maxCachedIPs)
	// IPv4 first: preserves legacy single-dial behavior for the common
	// case (first dial usually wins instantly, backups only stagger in
	// when it fails). The race, not the order, handles the rest.
	for _, a := range addrs {
		if len(ips) >= maxCachedIPs {
			break
		}
		if a.IP.To4() != nil {
			ips = append(ips, a.IP.String())
		}
	}
	for _, a := range addrs {
		if len(ips) >= maxCachedIPs {
			break
		}
		if a.IP.To4() == nil {
			ips = append(ips, a.IP.String())
		}
	}
	dnsCache.Lock()
	dnsCache.m[host] = cachedIPs{ips: ips, exp: now.Add(dnsCacheTTL)}
	// opportunistic sweep
	if len(dnsCache.m) > 10000 {
		for k, v := range dnsCache.m {
			if now.After(v.exp) {
				delete(dnsCache.m, k)
			}
		}
	}
	dnsCache.Unlock()
	return ips
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

func sealRecordFast(aead interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
}, data []byte, total int) []byte {
	budget := total - 2 - 12 - 16
	if len(data) > budget-2 {
		data = data[:budget-2]
	}
	padLen := budget - 2 - len(data)
	tmp := make([]byte, 12+padLen)
	if _, err := rand.Read(tmp); err != nil {
		panic(err)
	}
	pt := make([]byte, budget)
	binary.BigEndian.PutUint16(pt[:2], uint16(len(data)))
	copy(pt[2:], data)
	copy(pt[2+len(data):], tmp[12:])
	out := make([]byte, 0, total)
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(total-2))
	out = append(out, hdr[:]...)
	out = append(out, tmp[:12]...)
	out = append(out, aead.Seal(nil, tmp[:12], pt, nil)...)
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
	budget := total - 2 - 12 - 16
	if len(body) != total-2 || budget < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	pt, err := aead.Open(nil, body[:12], body[12:], nil)
	if err != nil {
		return nil, err
	}
	ln := int(binary.BigEndian.Uint16(pt[:2]))
	if ln < 0 || 2+ln > len(pt) {
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

// muxOn gates 0x04 sessions. SPECTER_MUX=off enforces legacy-only;
// anything else (incl. unset) enables mux. No guard.sh change needed.
var muxOn = func() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("SPECTER_MUX")))
	return v != "off"
}()

// ---------- mux frames (0x04 TCP sessions, one frame per record) ----------
// header: sid u32be | flags u8 | dlen u16be. Trunk is a single ordered TCP
// stream so frames never reorder; no per-stream sequence numbers needed.
const (
	muxFrameHdr = 7
	muxSYN      = 0x01 // client->server open, data = target atyp+addr+port
	muxDATA     = 0x02
	muxFIN      = 0x04
	muxRST      = 0x08
	muxSYNACK   = 0x10 // server->client open-ok
	muxSYNFAIL  = 0x20 // server->client open-failed

	muxMaxStreams = 256
	muxBufCap     = 8 << 20 // global queued-bytes backpressure threshold
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

// checkHandshake verifies tag over ver||magic||nonce||ephC for either
// wire version. Version POLICY is enforced by the caller after HMAC so
// every rejection (bad tag, mux-off, unknown ver) looks identical: silent.
func checkHandshake(hs []byte) (nonce, ephC []byte, ok bool) {
	if len(hs) != 69 || (hs[0] != version && hs[0] != muxVersion) {
		return nil, nil, false
	}
	m := hmac.New(sha256.New, psk)
	m.Write(hs[:53])
	if !hmac.Equal(m.Sum(nil)[:16], hs[53:69]) {
		return nil, nil, false
	}
	return append([]byte(nil), hs[5:21]...), append([]byte(nil), hs[21:53]...), true
}

func serverReply(ver byte, ephS, ephC, nonce []byte) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte{ver})
	m.Write(ephS)
	m.Write(ephC)
	m.Write(nonce)
	out := make([]byte, 0, 49)
	out = append(out, ver)
	out = append(out, ephS...)
	out = append(out, m.Sum(nil)[:16]...)
	return out
}

func handleTCP(c net.Conn, sem chan struct{}) {
	defer c.Close()
	defer func() { <-sem }()
	tuneTCP(c)
	statInc("tcp_accept")
	remote := c.RemoteAddr().String()
	hs := make([]byte, 69)
	if _, err := io.ReadFull(c, hs); err != nil {
		logRL("tcp-hs", logDebug, 5*time.Second, "hs read fail remote=%s err=%v", remote, err)
		statInc("tcp_hs_reject")
		return
	}
	nonce, ephC, ok := checkHandshake(hs)
	if !ok {
		logRL("tcp-hs", logDebug, 5*time.Second, "hs reject (bad ver/tag) remote=%s", remote)
		statInc("tcp_hs_reject")
		return
	}
	if nonceSeen(nonce) {
		logRL("tcp-hs", logDebug, 5*time.Second, "hs replay remote=%s", remote)
		statInc("tcp_hs_reject")
		return
	}
	ver := hs[0]
	if ver == muxVersion && !muxOn {
		logRL("tcp-hs", logDebug, 5*time.Second, "mux refused (disabled) remote=%s", remote)
		return // silent close, same as bad tag; client auto-falls-back
	}
	ephSPriv, ephSPub := genEphemeral()
	shared, err := curve25519.X25519(ephSPriv, ephC)
	if err != nil {
		return
	}
	sk := fsKey(shared)
	sk0 := hsKey(nonce)
	aead, _ := chacha20poly1305.New(sk)
	aead0, _ := chacha20poly1305.New(sk0)
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.Write(serverReply(ver, ephSPub, ephC, nonce)); err != nil {
		logRL("tcp-hs", logDebug, 5*time.Second, "hs reply write fail remote=%s err=%v", remote, err)
		return
	}
	if ver == muxVersion {
		logf(logDebug, "mux trunk from %s", remote)
		handleMux(c, aead)
		return
	}
	// first record carries the target under the hello key (0-RTT: the
	// client sends hs+target together before seeing our reply)
	tgt, err := readRecordFast(c, aead0)
	if err != nil {
		logf(logDebug, "tcp target record fail remote=%s err=%v", remote, err)
		return
	}
	host, rest, ok := parseAddr(tgt)
	if !ok || len(rest) < 2 {
		logf(logDebug, "tcp bad target remote=%s", remote)
		return
	}
	t, err := dialTarget("tcp", host, itoa(int(binary.BigEndian.Uint16(rest[:2]))))
	if err != nil {
		return
	}
	statInc("tcp_hs_ok")
	defer t.Close()
	tuneTCP(t)
	c.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			d, err := readRecordFast(c, aead)
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
		sent := 0
		for {
			t.SetDeadline(time.Now().Add(3 * time.Minute))
			n, err := t.Read(buf)
			if err != nil || n == 0 {
				return
			}
			c.SetDeadline(time.Now().Add(3 * time.Minute))
			off := 0
			for off < n {
				total := pickClassLatency(tcpClasses, sent)
				end := off + total - 2 - 12 - 16 - 2
				if end > n {
					end = n
				}
				if _, err := c.Write(sealRecordFast(aead, buf[off:end], total)); err != nil {
					return
				}
				sent += end - off
				off = end
			}
		}
	}()
	<-done
}

// ---------- mux dispatcher (0x04 TCP sessions) ----------

type muxServerStream struct {
	id     uint32
	target net.Conn
	q      chan []byte // trunk -> target payloads; nil chunk = FIN
	dead   chan struct{}
}

// handleMux takes over a verified 0x04 connection (sem released by caller
// on return). One TCP trunk carries many streams; frames arrive in order.
func handleMux(c net.Conn, aead cipher.AEAD) {
	defer c.Close()
	c.SetDeadline(time.Time{})
	tuneTCP(c)
	var mu sync.Mutex
	streams := map[uint32]*muxServerStream{}
	var wmu sync.Mutex
	var sentBytes int
	var buffered int64
	remote := c.RemoteAddr().String()

	// sendFrame writes one frame in one class-sized record.
	sendFrame := func(sid uint32, flags byte, data []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		total := pickClassLatency(tcpClasses, sentBytes)
		sentBytes += len(data)
		_, err := c.Write(sealRecordFast(aead, muxEncode(sid, flags, data), total))
		return err
	}
	// writeData chunks an arbitrary payload into DATA frames.
	writeData := func(sid uint32, data []byte) error {
		for len(data) > 0 {
			wmu.Lock()
			total := pickClassLatency(tcpClasses, sentBytes)
			n := total - 2 - 12 - 16 - 2 - muxFrameHdr
			if n > len(data) {
				n = len(data)
			}
			rec := sealRecordFast(aead, muxEncode(sid, muxDATA, data[:n]), total)
			sentBytes += n
			_, err := c.Write(rec)
			wmu.Unlock()
			if err != nil {
				return err
			}
			data = data[n:]
		}
		return nil
	}
	killStream := func(sid uint32) {
		mu.Lock()
		st, ok := streams[sid]
		if ok {
			delete(streams, sid)
		}
		mu.Unlock()
		if ok {
			close(st.dead)
			st.target.Close()
		}
	}
	openStream := func(sid uint32, tgt []byte) {
		mu.Lock()
		n := len(streams)
		mu.Unlock()
		if n >= muxMaxStreams {
			logRL("mux", logWarn, 10*time.Second, "stream cap %d, refusing sid=%d from %s", muxMaxStreams, sid, remote)
			_ = sendFrame(sid, muxSYNFAIL, nil)
			return
		}
		host, rest, ok := parseAddr(tgt)
		if !ok || len(rest) != 2 {
			_ = sendFrame(sid, muxSYNFAIL, nil)
			return
		}
		t, err := dialTarget("mux", host, itoa(int(binary.BigEndian.Uint16(rest[:2]))))
		if err != nil {
			_ = sendFrame(sid, muxSYNFAIL, nil)
			return
		}
		tuneTCP(t)
		st := &muxServerStream{id: sid, target: t, q: make(chan []byte, 256), dead: make(chan struct{})}
		mu.Lock()
		if _, dup := streams[sid]; dup {
			mu.Unlock()
			t.Close()
			return
		}
		streams[sid] = st
		mu.Unlock()
		if err := sendFrame(sid, muxSYNACK, nil); err != nil {
			killStream(sid)
			return
		}
		done := make(chan struct{}, 2)
		go func() { // trunk -> target
			defer func() { done <- struct{}{} }()
			for {
				select {
				case chunk := <-st.q:
					if chunk == nil {
						closeWrite(t)
						return
					}
					atomic.AddInt64(&buffered, -int64(len(chunk)))
					t.SetDeadline(time.Now().Add(3 * time.Minute))
					if _, err := t.Write(chunk); err != nil {
						return
					}
				case <-st.dead:
					return
				}
			}
		}()
		go func() { // target -> trunk
			defer func() { done <- struct{}{} }()
			buf := make([]byte, 1388)
			for {
				t.SetDeadline(time.Now().Add(3 * time.Minute))
				n, err := t.Read(buf)
				if err != nil || n == 0 {
					return
				}
				if err := writeData(sid, buf[:n]); err != nil {
					return
				}
			}
		}()
		go func() { // reaper: both directions done -> teardown
			<-done
			<-done
			killStream(sid)
		}()
	}

	for {
		// Global backpressure: pause reading while queued bytes are high.
		// Pumps always drain, so this cannot deadlock.
		for atomic.LoadInt64(&buffered) > muxBufCap {
			time.Sleep(5 * time.Millisecond)
		}
		c.SetDeadline(time.Now().Add(3 * time.Minute))
		d, err := readRecordFast(c, aead)
		if err != nil {
			logf(logDebug, "mux trunk end remote=%s err=%v", remote, err)
			break
		}
		sid, flags, data, ok := muxDecode(d)
		if !ok {
			logf(logDebug, "mux bad frame remote=%s", remote)
			continue
		}
		switch {
		case flags&muxSYN != 0:
			openStream(sid, data)
		case flags&(muxFIN|muxRST) != 0:
			mu.Lock()
			st, known := streams[sid]
			mu.Unlock()
			if known {
				if len(data) > 0 {
					atomic.AddInt64(&buffered, int64(len(data)))
					select {
					case st.q <- data:
					case <-st.dead:
						atomic.AddInt64(&buffered, -int64(len(data)))
					}
				}
				if flags&muxFIN != 0 {
					// Ordered trunk: all DATA precedes this FIN.
					select {
					case st.q <- nil:
					case <-st.dead:
					}
				}
				if flags&muxRST != 0 {
					killStream(sid)
				}
			}
		default: // DATA (possibly with stray bits)
			mu.Lock()
			st, known := streams[sid]
			mu.Unlock()
			if !known {
				_ = sendFrame(sid, muxRST, nil)
				continue
			}
			atomic.AddInt64(&buffered, int64(len(data)))
			select {
			case st.q <- data:
			case <-st.dead:
				atomic.AddInt64(&buffered, -int64(len(data)))
			}
		}
	}
	// Trunk dead: reset everything so clients retrunk on demand.
	mu.Lock()
	ids := make([]uint32, 0, len(streams))
	for id := range streams {
		ids = append(ids, id)
	}
	mu.Unlock()
	for _, id := range ids {
		killStream(id)
	}
	if len(ids) > 0 {
		logf(logWarn, "mux trunk dead remote=%s reset=%d streams", remote, len(ids))
	}
}

// ---------- UDP ----------

// Datagram flag bits. 0x01/0x02 predate ACKs; 0x04 marks ACK-capable
// clients, 0x08 marks server ACK datagrams (only sent when the session
// advertised 0x04, so old clients never see them).
const (
	udpFlagHello  = 0x01
	udpFlagEarly  = 0x02
	udpFlagAckCap = 0x04
	udpFlagAck    = 0x08
)

type udpSession struct {
	target    net.Conn
	sendSeq   uint32
	expect    uint32
	pending   map[uint32][]byte
	gapSince  time.Time
	last      time.Time
	sk        []byte // FS data key
	sk0       []byte // hello/early key (PSK-derived)
	aeadFS    cipher.AEAD
	aead0     cipher.AEAD
	peerReady bool   // client proved FS key (first sk datagram seen)
	ackOK     bool   // client advertised ACK support (flag 0x04)
	rxCount   uint64 // data datagrams received (ACK every 2nd + on gap)
	ephS      []byte
	ephC      []byte
	hsNonce   []byte
	sid       []byte
	peer      *net.UDPAddr
	sentBytes int
	mu        sync.Mutex
}

var (
	udpMu       sync.Mutex
	udpSessions = map[string]*udpSession{}
	// O(1) sid -> session index (roaming-safe). udpSessions stays as owner map.
	udpBySID = map[string]*udpSession{}
)

// Orphan early-data: datagrams arriving before their hello finished its
// TCP dial (hello always loses the race — dial takes ms, packets take µs).
// Old code slept 5x20ms here: every fresh connection paid +20ms jitter and
// anything with dial >100ms lost its first data forever (no UDP retransmit
// => hung connection). Instead park them with zero sleep and flush on
// session insert. Bounded: 64/sid, 4096 sids, 2s expiry.
type orphanPkt struct {
	pkt  []byte
	addr *net.UDPAddr
	at   time.Time
}

var orphanMu sync.Mutex
var orphans = map[string][]orphanPkt{}

const (
	orphanMaxPerSid = 64
	orphanMaxSids   = 4096
	orphanTTL       = 2 * time.Second
)

func stashOrphan(sid, pkt []byte, addr *net.UDPAddr) {
	orphanMu.Lock()
	defer orphanMu.Unlock()
	k := string(sid)
	if len(orphans) >= orphanMaxSids && orphans[k] == nil {
		now := time.Now()
		for kk, vv := range orphans {
			if len(vv) == 0 || now.Sub(vv[0].at) > orphanTTL {
				delete(orphans, kk)
			}
		}
		if len(orphans) >= orphanMaxSids {
			return // shed under flood
		}
	}
	if len(orphans[k]) >= orphanMaxPerSid {
		return
	}
	orphans[k] = append(orphans[k], orphanPkt{pkt: pkt, addr: addr, at: time.Now()})
}

// drainOrphans delivers parked early-data now that the session exists.
// Must be called after the session is visible in udpBySID.
func drainOrphans(s *udpSession) {
	orphanMu.Lock()
	list := orphans[string(s.sid)]
	delete(orphans, string(s.sid))
	orphanMu.Unlock()
	if len(list) > 0 {
		statAdd("orphan_drained", uint64(len(list)))
		logf(logDebug, "orphan drain sid=%x n=%d", s.sid, len(list))
	}
	for _, o := range list {
		if openDeliver(s, o.pkt) {
			s.mu.Lock()
			s.peer = o.addr
			s.mu.Unlock()
		}
	}
}

func sweepOrphans() {
	now := time.Now()
	var expired uint64
	orphanMu.Lock()
	for k, vv := range orphans {
		if len(vv) == 0 || now.Sub(vv[0].at) > orphanTTL {
			delete(orphans, k)
			expired += uint64(len(vv))
		}
	}
	orphanMu.Unlock()
	if expired > 0 {
		statAdd("orphan_expired", expired)
		logf(logDebug, "orphan sweep expired=%d", expired)
	}
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
				delete(udpBySID, string(s.sid))
				statInc("udp_done")
			}
		}
		udpMu.Unlock()
		sweepOrphans()
	}
}

func lookupSession(sid []byte) (*udpSession, string) {
	k := string(sid)
	udpMu.Lock()
	defer udpMu.Unlock()
	if s, ok := udpBySID[k]; ok {
		// find owner key for pump cleanup compatibility
		for ok2, v := range udpSessions {
			if v == s {
				return v, ok2
			}
		}
		return s, k
	}
	return nil, ""
}

func lookupSessionFast(sid []byte) *udpSession {
	udpMu.Lock()
	s := udpBySID[string(sid)]
	udpMu.Unlock()
	return s
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

func openDgramFast(aead interface {
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}, sid []byte, pkt []byte) (flags byte, seq uint32, data []byte, ok bool) {
	if !validClass(udpClasses, len(pkt)) || len(pkt) < 8+12+1+4+2+16 {
		return 0, 0, nil, false
	}
	if string(pkt[:8]) != string(sid) {
		return 0, 0, nil, false
	}
	flags = pkt[20]
	seq = binary.BigEndian.Uint32(pkt[21:25])
	ad := make([]byte, 0, 13)
	ad = append(ad, sid...)
	ad = append(ad, flags)
	ad = append(ad, pkt[21:25]...)
	pt, err := aead.Open(nil, pkt[8:20], pkt[25:], ad)
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

// pacer smooths UDP bursts (token bucket) so big responses don't
// overflow socket buffers and collapse into mass loss.
type pacer struct {
	mu     sync.Mutex
	rate   float64
	tokens float64
	last   time.Time
}

// udpMbps reads SPECTER_UDP_MBPS (default 100). Raise on fast paths,
// lower on thin/lossy ones. Throughput can never exceed what the path
// and the client's reorder buffer sustain. First 64KB per session bypass
// pacing (interactive burst), so browsing TTFB isn't throttled.
func udpMbps() float64 {
	if v := os.Getenv("SPECTER_UDP_MBPS"); v != "" {
		var f float64
		if _, err := fmt.Sscanf(v, "%f", &f); err == nil && f >= 1 && f <= 10000 {
			return f
		}
	}
	return 100
}

func newPacer(bps float64) *pacer {
	return &pacer{rate: bps, tokens: 65536, last: time.Now()}
}

func (p *pacer) wait(n int) {
	p.mu.Lock()
	now := time.Now()
	p.tokens += now.Sub(p.last).Seconds() * p.rate
	if p.tokens > 256*1024 {
		p.tokens = 256 * 1024
	}
	p.last = now
	need := float64(n)
	if p.tokens >= need {
		p.tokens -= need
		p.mu.Unlock()
		return
	}
	deficit := need - p.tokens
	p.tokens = 0
	p.mu.Unlock()
	time.Sleep(time.Duration(deficit / p.rate * float64(time.Second)))
	p.mu.Lock()
	p.last = time.Now()
	p.mu.Unlock()
}

func udpPump(conn *net.UDPConn, key string, addr *net.UDPAddr, sid, sk []byte, s *udpSession) {
	buf := make([]byte, udpMaxPayload)
	pacer := newPacer(udpMbps() * (1 << 20)) // smooths bursts past socket buffers
	aeadFS, _ := chacha20poly1305.New(sk)
	s.mu.Lock()
	aead0, _ := chacha20poly1305.New(s.sk0)
	s.mu.Unlock()
	for {
		s.target.SetDeadline(time.Now().Add(3 * time.Minute))
		n, err := s.target.Read(buf)
		if err != nil || n == 0 {
			logf(logDebug, "udp pump end sid=%x err=%v", sid, err)
			break
		}
		s.mu.Lock()
		seq := s.sendSeq
		s.sendSeq++
		s.last = time.Now()
		useEarly := !s.peerReady
		sent := s.sentBytes
		// capture current peer (roaming-safe)
		peer := s.peer
		if peer == nil {
			peer = addr
		}
		s.mu.Unlock()
		aead := aeadFS
		var fl byte
		if useEarly {
			// early replies share sk0 path until client proves FS key
			aead = aead0
		}
		total := pickClassLatency(udpClasses, sent)
		budget := total - 25 - 16
		off := 0
		for off < n {
			end := off + budget - 2
			if end > n {
				end = n
			}
			ptLen := end - off
			padLen := budget - 2 - ptLen
			tmp := make([]byte, 12+padLen)
			if _, err := rand.Read(tmp); err != nil {
				break
			}
			pt := make([]byte, budget)
			binary.BigEndian.PutUint16(pt[:2], uint16(ptLen))
			copy(pt[2:], buf[off:end])
			copy(pt[2+ptLen:], tmp[12:])
			ad := append(append(append([]byte(nil), sid...), fl), uint32be(seq)...)
			ct := aead.Seal(nil, tmp[:12], pt, ad)
			out := make([]byte, 0, total)
			out = append(out, sid...)
			out = append(out, tmp[:12]...)
			out = append(out, fl)
			out = append(out, uint32be(seq)...)
			out = append(out, ct...)
			conn.WriteToUDP(out, peer)
			// Interactive bypass: first 64KB bursts straight through.
			s.mu.Lock()
			bypass := s.sentBytes < pacerBypassBytes
			s.sentBytes += len(out)
			s.mu.Unlock()
			if !bypass {
				pacer.wait(len(out))
			}
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
		delete(udpBySID, string(s.sid))
		statInc("udp_done")
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
		if err != nil {
			logf(logDebug, "udp deliver write fail sid=%x err=%v", s.sid, err)
			return false
		}
		return true
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
		logRL("udp", logDebug, 5*time.Second, "bad size %d from %s", len(pkt), addr)
		return
	}
	// Data for known session: O(1) lookup, no linear scan, no sleep.
	// Unknown sid + non-hello: 0-RTT early data that beat its hello here
	// (hello is still TCP-dialing). Park it; drainOrphans flushes on insert.
	if len(pkt) >= 8 {
		if s := lookupSessionFast(pkt[:8]); s != nil {
			if openDeliver(s, pkt) {
				s.mu.Lock()
				s.peer = addr
				s.mu.Unlock()
				maybeAck(conn, s)
				return
			}
			if pkt[0] == version {
				s.mu.Lock()
				sid, ephS, ephC, hsNonce := s.sid, s.ephS, s.ephC, s.hsNonce
				s.mu.Unlock()
				logf(logDebug, "udp hello retry from %s, resending reply", addr)
				conn.WriteToUDP(helloReply(sid, ephS, ephC, hsNonce, udpClasses[0]), addr)
			} else {
				logRL("udp-data", logDebug, 5*time.Second, "open fail from %s", addr)
			}
			return
		}
		if pkt[0] != version {
			stashOrphan(pkt[:8], pkt, addr)
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
		// Not a hello (bad tag). Could be data whose random sid starts
		// with the version byte (1/256) — orphan it instead of dropping.
		logRL("udp-hello", logDebug, 5*time.Second, "hello tag mismatch from %s", addr)
		stashOrphan(pkt[:8], pkt, addr)
		statInc("udp_hello_reject")
		return
	}
	sid := append([]byte(nil), pkt[69:77]...)
	seq := binary.BigEndian.Uint32(pkt[77:81])
	flags := pkt[81]
	if flags&1 == 0 {
		return
	}
	if s := lookupSessionFast(sid); s != nil {
		// hello retransmit (client missed our reply): resend it
		logf(logDebug, "udp hello retry from %s, resending reply", addr)
		conn.WriteToUDP(helloReply(s.sid, s.ephS, s.ephC, s.hsNonce, udpClasses[0]), addr)
		return
	}
	if nonceSeen(hsNonce) {
		logRL("udp-hello", logDebug, 5*time.Second, "hello dup from %s", addr)
		return
	}
	sk0 := hsKey(hsNonce)
	a, _ := chacha20poly1305.New(sk0)
	ad := append(append(append([]byte(nil), sid...), flags), pkt[77:81]...)
	pt, err := a.Open(nil, hsNonce[:12], pkt[82:], ad)
	if err != nil || len(pt) != budget {
		logRL("udp-hello", logDebug, 5*time.Second, "hello open fail from %s err=%v", addr, err)
		statInc("udp_hello_reject")
		return
	}
	host, rest, ok := parseAddr(pt)
	if !ok || len(rest) < 2 {
		logRL("udp-hello", logDebug, 5*time.Second, "hello bad target from %s", addr)
		statInc("udp_hello_reject")
		return
	}
	_ = seq
	t, err := dialTarget("udp", host, itoa(int(binary.BigEndian.Uint16(rest[:2]))))
	if err != nil {
		return
	}
	statInc("udp_hello_ok")
	tuneTCP(t)
	ephSPriv, ephSPub := genEphemeral()
	shared, err := curve25519.X25519(ephSPriv, ephC)
	if err != nil {
		t.Close()
		return
	}
	sk := fsKey(shared)
	aeadFS, _ := chacha20poly1305.New(sk)
	aead0, _ := chacha20poly1305.New(sk0)
	key := addr.String() + "|" + string(sid)
	udpMu.Lock()
	if old, dup := udpSessions[key]; dup {
		old.target.Close()
		delete(udpBySID, string(old.sid))
	}
	s := &udpSession{target: t, pending: map[uint32][]byte{}, last: time.Now(),
		sk: append([]byte(nil), sk...), sk0: append([]byte(nil), sk0...),
		aeadFS: aeadFS, aead0: aead0, ackOK: flags&udpFlagAckCap != 0,
		ephS: ephSPub, ephC: ephC, hsNonce: hsNonce, sid: sid, peer: addr}
	udpSessions[key] = s
	udpBySID[string(sid)] = s
	udpMu.Unlock()
	drainOrphans(s)
	conn.WriteToUDP(helloReply(sid, ephSPub, ephC, hsNonce, udpClasses[0]), addr)
	go udpPump(conn, key, addr, sid, s.sk, s)
}

// openDeliver opens one data datagram (FS key, or hello key for early
// traffic) and delivers it.
func openDeliver(s *udpSession, pkt []byte) bool {
	s.mu.Lock()
	aeadFS, aead0 := s.aeadFS, s.aead0
	// fallback to byte keys if session predates AEAD fields (shouldn't happen)
	var sk, sk0 []byte
	if aeadFS == nil {
		sk = s.sk
	}
	if aead0 == nil {
		sk0 = s.sk0
	}
	s.mu.Unlock()
	if aeadFS != nil {
		if flags, seq, data, ok := openDgramFast(aeadFS, pkt[:8], pkt); ok {
			_ = flags
			s.mu.Lock()
			s.peerReady = true
			if flags&udpFlagAckCap != 0 {
				s.ackOK = true
			}
			s.rxCount++
			s.mu.Unlock()
			deliverUDP(s, seq, data)
			return true
		}
		if aead0 != nil {
			if flags, seq, data, ok := openDgramFast(aead0, pkt[:8], pkt); ok {
				_ = flags
				s.mu.Lock()
				if flags&udpFlagAckCap != 0 {
					s.ackOK = true
				}
				s.rxCount++
				s.mu.Unlock()
				deliverUDP(s, seq, data)
				return true
			}
			return false
		}
	}
	// legacy fallback (no cached AEAD)
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

// maybeAck sends a selective ACK (cumulative + 32-bit SACK) for sessions
// that advertised ACK support. Delayed-ACK policy: every 2nd datagram, or
// immediately when a gap is visible (fast signal for the missing seq, like
// TCP duplicate ACKs). Best-effort: loss of an ACK is harmless, the next
// one supersedes it. Smallest size class; never sent to old clients.
func maybeAck(conn *net.UDPConn, s *udpSession) {
	s.mu.Lock()
	if !s.ackOK {
		s.mu.Unlock()
		return
	}
	c := s.rxCount
	gap := len(s.pending) > 0
	if c%2 == 1 && !gap {
		s.mu.Unlock()
		return
	}
	cumul := s.expect - 1
	var mask uint32
	for i := 0; i < 32; i++ {
		if _, ok := s.pending[cumul+1+uint32(i)]; ok {
			mask |= 1 << uint(i)
		}
	}
	aead := s.aeadFS
	if !s.peerReady {
		aead = s.aead0
	}
	if aead == nil {
		s.mu.Unlock()
		return
	}
	sid := append([]byte(nil), s.sid...)
	peer := s.peer
	s.mu.Unlock()
	if peer == nil {
		return
	}
	total := udpClasses[0]
	budget := total - 25 - 16
	tmp := make([]byte, 12+budget-2-8)
	if _, err := rand.Read(tmp); err != nil {
		return
	}
	pt := make([]byte, budget)
	binary.BigEndian.PutUint16(pt[:2], 8)
	binary.BigEndian.PutUint32(pt[2:6], cumul)
	binary.BigEndian.PutUint32(pt[6:10], mask)
	copy(pt[10:], tmp[12:])
	ad := append(append(append([]byte(nil), sid...), udpFlagAck), uint32be(cumul)...)
	ct := aead.Seal(nil, tmp[:12], pt, ad)
	out := make([]byte, 0, total)
	out = append(out, sid...)
	out = append(out, tmp[:12]...)
	out = append(out, udpFlagAck)
	out = append(out, uint32be(cumul)...)
	out = append(out, ct...)
	conn.WriteToUDP(out, peer)
}

func udpLoop(uconn *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := uconn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		// Per-packet goroutine preserves concurrency under browsing fan-out
		// (5-20 parallel sessions). Inline handling would head-of-line block
		// the single loop on TCP Write to origin. O(1) lookup keeps it cheap.
		pkt := append([]byte(nil), buf[:n]...)
		go handleUDP(uconn, addr, pkt)
	}
}

func main() {
	mode := os.Getenv("SPECTER_TRANSPORT") // tcp | udp | both (default both)
	if mode != "tcp" && mode != "udp" && mode != "" && mode != "both" {
		logf(logWarn, "unknown SPECTER_TRANSPORT=%q, serving tcp+udp", mode)
	}
	listen := listenAddr()
	muxStr := "on"
	if !muxOn {
		muxStr = "off"
	}
	log.Printf("specter-server %s listen=%s mode=%s mux=%s log=%s", appVersion, listen, mode, muxStr, os.Getenv("SPECTER_LOG"))
	var ln net.Listener
	if mode != "udp" {
		var err error
		ln, err = net.Listen("tcp", listen)
		if err != nil {
			panic(err)
		}
	}
	if mode != "tcp" {
		uaddr, err := net.ResolveUDPAddr("udp", listen)
		if err != nil {
			panic(err)
		}
		uconn, err := net.ListenUDP("udp", uaddr)
		if err != nil {
			panic(err)
		}
		_ = uconn.SetReadBuffer(4 << 20)
		_ = uconn.SetWriteBuffer(4 << 20)
		go udpLoop(uconn)
	}
	go nonceSweeper()
	go udpReaper()
	go statReport()
	if ln == nil {
		select {} // UDP-only mode: just wait
	}
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
			logRL("tcp-conn", logWarn, 10*time.Second, "at maxConns=%d, dropping %s", maxConns, c.RemoteAddr())
			statInc("tcp_accept_drop")
			c.Close()
		}
	}
}
