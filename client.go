package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/minio/blake2b-simd"
	"github.com/yawning/chacha20"
	"golang.org/x/crypto/ed25519"
)

func copyOperation(conf Conf, h1 []byte, reader *bufio.Reader, writer *bufio.Writer) {
	content, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	nonce := make([]byte, 24)
	if _, err = rand.Read(nonce); err != nil {
		log.Fatal(err)
	}
	cipher, err := chacha20.NewCipher(conf.EncryptSk, nonce)
	if err != nil {
		log.Fatal(err)
	}
	opcode := byte('S')
	ciphertextWithNonce := make([]byte, 24+len(content))
	copy(ciphertextWithNonce, nonce)
	ciphertext := ciphertextWithNonce[24:]
	cipher.XORKeyStream(ciphertext, content)
	signature := ed25519.Sign(conf.SignSk, ciphertextWithNonce)
	hf2, _ := blake2b.New(&blake2b.Config{
		Key:    conf.Psk,
		Person: []byte(domainStr),
		Size:   32,
		Salt:   []byte{2},
	})
	hf2.Write(h1)
	hf2.Write([]byte{opcode})
	hf2.Write(conf.EncryptSkID)
	hf2.Write(signature)
	h2 := hf2.Sum(nil)

	writer.WriteByte(opcode)
	writer.Write(h2)
	ciphertextWithNonceLen := uint64(len(ciphertextWithNonce))
	binary.Write(writer, binary.LittleEndian, ciphertextWithNonceLen)
	writer.Write(conf.EncryptSkID)
	writer.Write(signature)
	writer.Write(ciphertextWithNonce)
	if err := writer.Flush(); err != nil {
		log.Print(err)
		return
	}
	rbuf := make([]byte, 32)
	if _, err = io.ReadFull(reader, rbuf); err != nil {
		log.Print(err)
		return
	}
	h3 := rbuf
	hf3, _ := blake2b.New(&blake2b.Config{
		Key:    conf.Psk,
		Person: []byte(domainStr),
		Size:   32,
		Salt:   []byte{3},
	})
	hf3.Write(h2)
	wh3 := hf3.Sum(nil)
	if subtle.ConstantTimeCompare(wh3, h3) != 1 {
		return
	}
	fmt.Println("Sent and ACK'd by the server")
}

func pasteOperation(conf Conf, h1 []byte, reader *bufio.Reader,
	writer *bufio.Writer, isMove bool) {
	opcode := byte('G')
	if isMove {
		opcode = byte('M')
	}
	hf2, _ := blake2b.New(&blake2b.Config{
		Key:    conf.Psk,
		Person: []byte(domainStr),
		Size:   32,
		Salt:   []byte{2},
	})
	hf2.Write(h1)
	hf2.Write([]byte{opcode})
	h2 := hf2.Sum(nil)
	writer.WriteByte(opcode)
	writer.Write(h2)
	if err := writer.Flush(); err != nil {
		log.Print(err)
		return
	}
	rbuf := make([]byte, 112)
	if _, err := io.ReadFull(reader, rbuf); err != nil {
		log.Print(err)
		return
	}
	h3 := rbuf[0:32]
	ciphertextWithNonceLen := binary.LittleEndian.Uint64(rbuf[32:40])
	encryptSkID := rbuf[40:48]
	_ = encryptSkID
	signature := rbuf[48:112]
	hf3, _ := blake2b.New(&blake2b.Config{
		Key:    conf.Psk,
		Person: []byte(domainStr),
		Size:   32,
		Salt:   []byte{3},
	})
	hf3.Write(h2)
	hf3.Write(encryptSkID)
	hf3.Write(signature)
	wh3 := hf3.Sum(nil)
	if subtle.ConstantTimeCompare(wh3, h3) != 1 {
		return
	}
	if bytes.Equal(conf.EncryptSkID, encryptSkID) == false {
		wEncryptSkIDStr := binary.LittleEndian.Uint64(conf.EncryptSkID)
		encryptSkIDStr := binary.LittleEndian.Uint64(encryptSkID)
		log.Fatal(fmt.Sprintf("Configured key ID is %v but content was encrypted using key ID %v",
			wEncryptSkIDStr, encryptSkIDStr))
	}
	ciphertextWithNonce := make([]byte, ciphertextWithNonceLen)
	if _, err := io.ReadFull(reader, ciphertextWithNonce); err != nil {
		log.Print(err)
		return
	}
	if ed25519.Verify(conf.SignPk, ciphertextWithNonce, signature) != true {
		return
	}
	nonce := ciphertextWithNonce[0:24]
	cipher, err := chacha20.NewCipher(conf.EncryptSk, nonce)
	if err != nil {
		log.Fatal(err)
	}
	ciphertext := ciphertextWithNonce[24:]
	cipher.XORKeyStream(ciphertext, ciphertext)
	content := ciphertext
	binary.Write(os.Stdout, binary.LittleEndian, content)
}

// ClientMain - Process a client query
func ClientMain(conf Conf, isCopy bool, isMove bool) {
	conn, err := net.Dial("tcp", conf.Connect)
	if err != nil {
		log.Fatal(fmt.Sprintf("Unable to connect to %v - Is a Piknik server running on that host?",
			conf.Connect))
	}
	r := make([]byte, 32)
	if _, err = rand.Read(r); err != nil {
		log.Fatal(err)
	}
	hf0, _ := blake2b.New(&blake2b.Config{
		Key:    conf.Psk,
		Person: []byte(domainStr),
		Size:   32,
		Salt:   []byte{0},
	})
	version := byte(4)
	hf0.Write([]byte{version})
	hf0.Write(r)
	h0 := hf0.Sum(nil)
	writer := bufio.NewWriter(conn)
	writer.Write([]byte{version})
	writer.Write(r)
	writer.Write(h0)
	if err := writer.Flush(); err != nil {
		log.Print(err)
		return
	}
	reader := bufio.NewReader(conn)
	rbuf := make([]byte, 65)
	if _, err = io.ReadFull(reader, rbuf); err != nil {
		log.Fatal(fmt.Sprintf("Incompatible server version (expected version: %v)", version))
	}
	if rbuf[0] != version {
		log.Fatal(fmt.Sprintf("Incompatible server version (client version: %v - server version: %v)",
			version, rbuf[0]))
	}
	r2 := rbuf[1:33]
	h1 := rbuf[33:65]
	hf1, _ := blake2b.New(&blake2b.Config{
		Key:    conf.Psk,
		Person: []byte(domainStr),
		Size:   32,
		Salt:   []byte{1},
	})
	hf1.Write([]byte{version})
	hf1.Write(r2)
	hf1.Write(h0)
	wh1 := hf1.Sum(nil)
	if subtle.ConstantTimeCompare(wh1, h1) != 1 {
		return
	}
	if isCopy {
		copyOperation(conf, h1, reader, writer)
	} else {
		pasteOperation(conf, h1, reader, writer, isMove)
	}
}
