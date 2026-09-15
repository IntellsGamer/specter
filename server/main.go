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

func main() {
	ln, err := net.Listen("tcp", listenAddr())
	if err != nil {
		panic(err)
	}
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
