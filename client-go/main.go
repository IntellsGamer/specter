package main

// Specter v3 client (Go): SOCKS5 on 127.0.0.1:10867 -> Specter AEAD protocol.
// Config: config.json (server/port/psk/transport) or argv path. Env overrides.

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
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	version     = 0x02
	cellSize    = 1024
	cellPT      = 996
	cellData    = 994
	dgramSize   = 1280
	dgramPT     = 1239
	dgramData   = 1237
	firstPT     = 1182
	udpChunk    = 1200
	udpReorder  = 64
	udpGapWait  = 300 * time.Millisecond
	socksListen = "127.0.0.1:10867"
)

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
	missing := cfg.Server == "" || cfg.Server == "YOUR_SERVER_IP" ||
		cfg.Psk == "" || (len(cfg.Psk) >= 7 && cfg.Psk[:7] == "REPLACE")
	if missing {
		// first run: drop a dummy config next to the binary so the user
		// has something to fill in, then explain via GUI if present.
		// Never overwrite an existing file.
		if cfgPath != "" {
			if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
				dummy, _ := json.MarshalIndent(Config{
					Server:    "203.0.113.10",
					Port:      43117,
					Psk:       "REPLACE_WITH_64_HEX_CHARS_FROM_SERVER",
					Transport: "tcp",
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
	if cfg.Transport == "" {
		cfg.Transport = "tcp"
	}
	if cfg.Transport != "tcp" && cfg.Transport != "udp" {
		log.Fatal(`transport must be "tcp" or "udp"`)
	}
	raw := cfg.Psk
	b, err := hex.DecodeString(raw)
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

// ---------- TCP ----------

func sealCell(sk, rnonce, data []byte) []byte {
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
	out := make([]byte, 0, cellSize)
	out = append(out, rnonce...)
	out = append(out, a.Seal(nil, rnonce, pt, nil)...)
	return out
}

func tcpLeg(app net.Conn, server string, port int, psk []byte, atyp byte, addr, portb []byte) {
	defer app.Close()
	magic := randBytes(4)
	nonce := randBytes(16)
	ephPriv, ephPub := genEphemeral()
	m := hmac.New(sha256.New, psk)
	m.Write([]byte{version})
	m.Write(magic)
	m.Write(nonce)
	m.Write(ephPub)
	tag := m.Sum(nil)[:16]
	up, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", server, port), 10*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	hs := make([]byte, 0, 69)
	hs = append(hs, version)
	hs = append(hs, magic...)
	hs = append(hs, nonce...)
	hs = append(hs, ephPub...)
	hs = append(hs, tag...)
	up.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := up.Write(hs); err != nil {
		return
	}
	rep := make([]byte, 49)
	if _, err := io.ReadFull(up, rep); err != nil {
		return
	}
	if rep[0] != version {
		return
	}
	ephS := rep[1:33]
	m2 := hmac.New(sha256.New, psk)
	m2.Write([]byte{version})
	m2.Write(ephS)
	m2.Write(ephPub)
	m2.Write(nonce)
	if !hmac.Equal(m2.Sum(nil)[:16], rep[33:49]) {
		return
	}
	shared, err := curve25519.X25519(ephPriv, ephS)
	if err != nil {
		return
	}
	sk := fsKey(psk, shared)
	tgt := append([]byte{atyp}, addr...)
	tgt = append(tgt, portb...)
	if _, err := up.Write(sealCell(sk, randBytes(12), tgt)); err != nil {
		return
	}
	if _, err := app.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		cell := make([]byte, cellSize)
		a, _ := chacha20poly1305.New(sk)
		for {
			if _, err := io.ReadFull(up, cell); err != nil {
				return
			}
			pt, err := a.Open(nil, cell[:12], cell[12:], nil)
			if err != nil {
				return
			}
			ln := int(binary.BigEndian.Uint16(pt[:2]))
			if ln > cellData {
				return
			}
			app.SetDeadline(time.Now().Add(3 * time.Minute))
			if _, err := app.Write(pt[2 : 2+ln]); err != nil {
				return
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, cellData)
		for {
			app.SetDeadline(time.Now().Add(3 * time.Minute))
			n, err := app.Read(buf)
			if err != nil || n == 0 {
				return
			}
			up.SetDeadline(time.Now().Add(3 * time.Minute))
			if _, err := up.Write(sealCell(sk, randBytes(12), buf[:n])); err != nil {
				return
			}
		}
	}()
	<-done
}

// ---------- UDP ----------

func sealDgram(sk, sid, rnonce []byte, flags byte, seq uint32, data []byte, budget int) []byte {
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
	out := make([]byte, 0, len(sid)+12+1+4+len(ct))
	out = append(out, sid...)
	out = append(out, rnonce...)
	out = append(out, flags)
	out = append(out, b[:]...)
	out = append(out, ct...)
	return out
}

func udpLeg(app net.Conn, server string, port int, psk []byte, atyp byte, addr, portb []byte) {
	defer app.Close()
	us, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", server, port), 10*time.Second)
	if err != nil {
		return
	}
	defer us.Close()
	magic := randBytes(4)
	hsNonce := randBytes(16)
	ephPriv, ephPub := genEphemeral()
	m := hmac.New(sha256.New, psk)
	m.Write([]byte{version})
	m.Write(magic)
	m.Write(hsNonce)
	m.Write(ephPub)
	tag := m.Sum(nil)[:16]
	sk0 := func() []byte {
		h := sha256.New()
		h.Write(psk)
		h.Write([]byte("specter-v3-hs"))
		h.Write(hsNonce)
		return h.Sum(nil)
	}()
	sid := randBytes(8)
	target := append([]byte{atyp}, addr...)
	target = append(target, portb...)

	// first datagram: ver+magic+hs+ephC+tag+sid+seq+flags+AEAD (fixed 1280)
	fpt := make([]byte, firstPT)
	copy(fpt, target)
	if _, err := rand.Read(fpt[len(target):]); err != nil {
		return
	}
	a, _ := chacha20poly1305.New(sk0)
	fad := make([]byte, 0, 13)
	fad = append(fad, sid...)
	fad = append(fad, 1)
	fad = append(fad, 0, 0, 0, 0)
	fct := a.Seal(nil, hsNonce[:12], fpt, fad)
	first := make([]byte, 0, dgramSize)
	first = append(first, version)
	first = append(first, magic...)
	first = append(first, hsNonce...)
	first = append(first, ephPub...)
	first = append(first, tag...)
	first = append(first, sid...)
	first = append(first, 0, 0, 0, 0, 1)
	first = append(first, fct...)
	var sk []byte
	deadline := time.Now().Add(8 * time.Second)
	for {
		us.SetDeadline(time.Now().Add(time.Second))
		if _, err := us.Write(first); err != nil {
			return
		}
		rep := make([]byte, dgramSize)
		us.SetDeadline(time.Now().Add(time.Second))
		n, err := us.Read(rep)
		if err != nil {
			if time.Now().After(deadline) {
				return
			}
			continue
		}
		rep = rep[:n]
		if len(rep) != dgramSize || string(rep[:8]) != string(sid) {
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
			return
		}
		sk = fsKey(psk, shared)
		break
	}
	if _, err := app.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	done := make(chan struct{})
	// sender
	go func() {
		defer close(done)
		var seq uint32
		buf := make([]byte, udpChunk)
		for {
			app.SetDeadline(time.Now().Add(3 * time.Minute))
			n, err := app.Read(buf)
			if err != nil || n == 0 {
				return
			}
			dg := sealDgram(sk, sid, randBytes(12), 0, seq, buf[:n], dgramPT)
			seq++
			us.SetDeadline(time.Now().Add(30 * time.Second))
			if _, err := us.Write(dg); err != nil {
				return
			}
		}
	}()
	// receiver with reorder
	defer func() { <-done }()
	expect := uint32(0)
	pending := map[uint32][]byte{}
	var gapSince time.Time
	rbuf := make([]byte, 2048)
	a2, _ := chacha20poly1305.New(sk)
	for {
		us.SetDeadline(time.Now().Add(3 * time.Minute))
		n, err := us.Read(rbuf)
		if err != nil {
			return
		}
		dg := rbuf[:n]
		if len(dg) != dgramSize || string(dg[:8]) != string(sid) {
			continue
		}
		pt, err := a2.Open(nil, dg[8:20], dg[25:], append(append(append([]byte(nil), dg[:8]...), dg[20]), dg[21:25]...))
		if err != nil {
			continue
		}
		seq := binary.BigEndian.Uint32(dg[21:25])
		ln := int(binary.BigEndian.Uint16(pt[:2]))
		if ln > dgramData || 2+ln > len(pt) {
			continue
		}
		data := append([]byte(nil), pt[2:2+ln]...)
		if seq < expect || pendingHas(pending, seq) {
			continue
		}
		if len(pending) < udpReorder {
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
			} else if time.Since(gapSince) > udpGapWait {
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

func pendingHas(m map[uint32][]byte, k uint32) bool {
	_, ok := m[k]
	return ok
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
		l, err2 := readN(app, 1)
		if err2 != nil {
			return
		}
		name, err2 := readN(app, int(l[0]))
		if err2 != nil {
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
	if transport == "udp" {
		udpLeg(app, server, port, psk, atyp, addr, portb)
		return
	}
	tcpLeg(app, server, port, psk, atyp, addr, portb)
}

func main() {
	server, port, psk, transport := loadConfig()
	ln, err := net.Listen("tcp", socksListen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("specter-go client [%s] socks5 %s -> %s:%d", transport, socksListen, server, port)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c, server, port, psk, transport)
	}
}
