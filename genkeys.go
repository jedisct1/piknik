package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"golang.org/x/crypto/ed25519"
)

func genKeys(conf Conf, configFile string) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		log.Fatal(err)
	}
	pskHex := hex.EncodeToString(psk)

	encryptSk := make([]byte, 32)
	if _, err := rand.Read(encryptSk); err != nil {
		log.Fatal(err)
	}
	encryptSkHex := hex.EncodeToString(encryptSk)

	signPk, signSk, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	signPkHex := hex.EncodeToString(signPk)
	signSkHex := hex.EncodeToString(signSk)

	fmt.Printf("\n\n--- Create a file named %s with only the lines relevant to your configuration ---\n\n\n", configFile)
	fmt.Printf("# Configuration for a client\n\n")
	fmt.Printf("Connect = %q\t# Edit appropriately\n", conf.Connect)
	fmt.Printf("EncryptSk = %q\n", encryptSkHex)
	fmt.Printf("Psk = %q\n", pskHex)
	fmt.Printf("SignPk = %q\n", signPkHex)
	fmt.Printf("SignSk = %q\n", signSkHex)

	fmt.Printf("\n\n")

	fmt.Printf("# Configuration for a server\n\n")
	fmt.Printf("Listen = %q\t# Edit appropriately\n", conf.Listen)
	fmt.Printf("Psk = %q\n", pskHex)
	fmt.Printf("SignPk = %q\n", signPkHex)

	fmt.Printf("\n\n")

	fmt.Printf("# Hybrid configuration\n\n")
	fmt.Printf("Connect = %q\t# Edit appropriately\n", conf.Connect)
	fmt.Printf("EncryptSk = %q\n", encryptSkHex)
	fmt.Printf("Listen = %q\t# Edit appropriately\n", conf.Listen)
	fmt.Printf("Psk = %q\n", pskHex)
	fmt.Printf("SignPk = %q\n", signPkHex)
	fmt.Printf("SignSk = %q\n", signSkHex)
}
