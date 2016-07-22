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

	"github.com/yawning/chacha20"
	"golang.org/x/crypto/ed25519"
)

// DefaultClientVersion - Default client version
const DefaultClientVersion = byte(4)

// Client - Client data
type Client struct {
	conf    Conf
	reader  *bufio.Reader
	writer  *bufio.Writer
	version byte
}

func (client *Client) copyOperation(h1 []byte) {
	conf, reader, writer := client.conf, client.reader, client.writer
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
	h2 := auth2store(conf, client.version, h1, opcode, signature)
	writer.WriteByte(opcode)
	writer.Write(h2)
	ciphertextWithNonceLen := uint64(len(ciphertextWithNonce))
	binary.Write(writer, binary.LittleEndian, ciphertextWithNonceLen)
	writer.Write(conf.EncryptSkID)
	writer.Write(signature)
	writer.Write(ciphertextWithNonce)
	if err := writer.Flush(); err != nil {
		log.Fatal(err)
	}
	rbuf := make([]byte, 32)
	if _, err = io.ReadFull(reader, rbuf); err != nil {
		log.Fatal(err)
	}
	h3 := rbuf
	wh3 := auth3store(conf, client.version, h2)
	if subtle.ConstantTimeCompare(wh3, h3) != 1 {
		log.Fatal("Incorrect authentication code")
	}
	fmt.Println("Sent")
}

func (client *Client) pasteOperation(h1 []byte, isMove bool) {
	conf, reader, writer := client.conf, client.reader, client.writer
	opcode := byte('G')
	if isMove {
		opcode = byte('M')
	}
	h2 := auth2get(conf, client.version, h1, opcode)
	writer.WriteByte(opcode)
	writer.Write(h2)
	if err := writer.Flush(); err != nil {
		log.Fatal(err)
	}
	rbuf := make([]byte, 112)
	if _, err := io.ReadFull(reader, rbuf); err != nil {
		log.Fatal(err)
	}
	h3 := rbuf[0:32]
	ciphertextWithNonceLen := binary.LittleEndian.Uint64(rbuf[32:40])
	encryptSkID := rbuf[40:48]
	_ = encryptSkID
	signature := rbuf[48:112]
	wh3 := auth3get(conf, client.version, h2, encryptSkID, signature)
	if subtle.ConstantTimeCompare(wh3, h3) != 1 {
		log.Fatal("Incorrect authentication code")
	}
	if bytes.Equal(conf.EncryptSkID, encryptSkID) == false {
		wEncryptSkIDStr := binary.LittleEndian.Uint64(conf.EncryptSkID)
		encryptSkIDStr := binary.LittleEndian.Uint64(encryptSkID)
		log.Fatal(fmt.Sprintf("Configured key ID is %v but content was encrypted using key ID %v",
			wEncryptSkIDStr, encryptSkIDStr))
	}
	ciphertextWithNonce := make([]byte, ciphertextWithNonceLen)
	if _, err := io.ReadFull(reader, ciphertextWithNonce); err != nil {
		log.Fatal(err)
	}
	if ed25519.Verify(conf.SignPk, ciphertextWithNonce, signature) != true {
		log.Fatal("Signature doesn't verify")
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

// RunClient - Process a client query
func RunClient(conf Conf, isCopy bool, isMove bool) {
	conn, err := net.Dial("tcp", conf.Connect)
	if err != nil {
		log.Fatal(fmt.Sprintf("Unable to connect to %v - Is a Piknik server running on that host?",
			conf.Connect))
	}
	defer conn.Close()
	reader, writer := bufio.NewReader(conn), bufio.NewWriter(conn)
	client := Client{
		conf:    conf,
		reader:  reader,
		writer:  writer,
		version: DefaultClientVersion,
	}
	r := make([]byte, 32)
	if _, err = rand.Read(r); err != nil {
		log.Fatal(err)
	}
	h0 := auth0(conf, client.version, r)
	writer.Write([]byte{client.version})
	writer.Write(r)
	writer.Write(h0)
	if err := writer.Flush(); err != nil {
		log.Fatal(err)
	}
	rbuf := make([]byte, 65)
	if _, err = io.ReadFull(reader, rbuf); err != nil {
		log.Fatal(fmt.Sprintf("Incompatible server version (expected version: %v)",
			client.version))
	}
	if serverVersion := rbuf[0]; serverVersion != client.version {
		log.Fatal(fmt.Sprintf("Incompatible server version (client version: %v - server version: %v)",
			client.version, serverVersion))
	}
	r2 := rbuf[1:33]
	h1 := rbuf[33:65]
	wh1 := auth1(conf, client.version, h0, r2)
	if subtle.ConstantTimeCompare(wh1, h1) != 1 {
		log.Fatal("Incorrect authentication code")
	}
	if isCopy {
		client.copyOperation(h1)
	} else {
		client.pasteOperation(h1, isMove)
	}
}
