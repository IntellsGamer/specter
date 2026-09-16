package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func main() {
	priv, _ := hex.DecodeString(os.Args[1])
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	fmt.Println("pub=" + hex.EncodeToString(pub))
	if len(os.Args) > 2 {
		peer, _ := hex.DecodeString(os.Args[2])
		shared, err := curve25519.X25519(priv, peer)
		if err != nil {
			panic(err)
		}
		fmt.Println("shared=" + hex.EncodeToString(shared))
		// HKDF-SHA256(shared, salt, info) 32B
		hk := hkdf.New(func() hash.Hash { return sha256.New() }, shared, []byte("SALT-TEST"), []byte("specter-v3"))
		sk := make([]byte, 32)
		if _, err := io.ReadFull(hk, sk); err != nil {
			panic(err)
		}
		fmt.Println("hkdf=" + hex.EncodeToString(sk))
	}
}
