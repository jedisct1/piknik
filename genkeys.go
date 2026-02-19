package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/scrypt"
)

// DeterministicRand - Deterministic random function
type DeterministicRand struct {
	pool []byte
	pos  int
}

var deterministicRand DeterministicRand

func initDeterministicRand(leKey []byte, poolLen int) {
	key, err := scrypt.Key(leKey, []byte{}, 16384, 12, 1, poolLen)
	if err != nil {
		log.Panic(err)
	}
	deterministicRand.pool, deterministicRand.pos = key, 0
}

func (DeterministicRand) Read(p []byte) (n int, err error) {
	reqLen := len(p)
	left := len(deterministicRand.pool) - deterministicRand.pos
	if left < reqLen {
		log.Panicf("rand pool exhaustion (%v left, %v needed)",
			left, reqLen)
	}
	copy(p, deterministicRand.pool[deterministicRand.pos:deterministicRand.pos+reqLen])
	for i := 0; i < reqLen; i++ {
		deterministicRand.pool[deterministicRand.pos+i] = 0
	}
	deterministicRand.pos += reqLen

	return reqLen, nil
}

func genKeys(conf Conf, configFile string, leKey string) {
	randRead, randReader := rand.Read, io.Reader(nil)
	if len(leKey) > 0 {
		initDeterministicRand([]byte(leKey), 96)
		randRead, randReader = deterministicRand.Read, deterministicRand
	}
	psk := make([]byte, 32)
	if _, err := randRead(psk); err != nil {
		log.Fatal(err)
	}
	pskHex := hex.EncodeToString(psk)

	encryptSk := make([]byte, 32)
	if _, err := randRead(encryptSk); err != nil {
		log.Fatal(err)
	}
	encryptSkHex := hex.EncodeToString(encryptSk)

	signPk, signSk, err := ed25519.GenerateKey(randReader)
	if err != nil {
		log.Fatal(err)
	}
	signPkHex := hex.EncodeToString(signPk)
	signSkHex := hex.EncodeToString(signSk[0:32])

	fmt.Printf("\n\n--- Create a file named %s with only the lines relevant to your configuration ---\n\n\n", configFile)
	fmt.Printf("# Configuration for a client\n\n")
	fmt.Printf("Connect   = %q\t# Edit appropriately\n", conf.Connect)
	fmt.Printf("Psk       = %q\n", pskHex)
	fmt.Printf("SignPk    = %q\n", signPkHex)
	fmt.Printf("SignSk    = %q\n", signSkHex)
	fmt.Printf("EncryptSk = %q\n", encryptSkHex)

	fmt.Printf("\n\n")

	fmt.Printf("# Configuration for a server\n\n")
	fmt.Printf("Listen = %q\t# Edit appropriately\n", conf.Listen)
	fmt.Printf("Psk    = %q\n", pskHex)
	fmt.Printf("SignPk = %q\n", signPkHex)

	fmt.Printf("\n\n")

	fmt.Printf("# Hybrid configuration\n\n")
	fmt.Printf("Connect   = %q\t# Edit appropriately\n", conf.Connect)
	fmt.Printf("Listen    = %q\t# Edit appropriately\n", conf.Listen)
	fmt.Printf("Psk       = %q\n", pskHex)
	fmt.Printf("SignPk    = %q\n", signPkHex)
	fmt.Printf("SignSk    = %q\n", signSkHex)
	fmt.Printf("EncryptSk = %q\n", encryptSkHex)
}

func getPassword(prompt string) string {
	os.Stdout.Write([]byte(prompt))
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	return strings.TrimSpace(password)
}
