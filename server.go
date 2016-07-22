package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"golang.org/x/crypto/ed25519"
)

// StoredContent - Paste buffer
type StoredContent struct {
	encryptSkID         []byte
	signature           []byte
	ciphertextWithNonce []byte
}

var storedContent StoredContent
var storedContentRWMutex sync.RWMutex

func getOperation(conf Conf, h1 []byte, reader *bufio.Reader,
	writer *bufio.Writer, clientVersion byte, isMove bool) {
	rbuf := make([]byte, 32)
	if _, err := io.ReadFull(reader, rbuf); err != nil {
		log.Print(err)
		return
	}
	h2 := rbuf
	opcode := byte('G')
	if isMove {
		opcode = byte('M')
	}
	wh2 := auth2get(conf, clientVersion, h1, opcode)
	if subtle.ConstantTimeCompare(wh2, h2) != 1 {
		return
	}

	var encryptSkID, signature, ciphertextWithNonce []byte
	if isMove {
		storedContentRWMutex.Lock()
		encryptSkID, signature, ciphertextWithNonce =
			storedContent.encryptSkID, storedContent.signature,
			storedContent.ciphertextWithNonce
		storedContent.encryptSkID, storedContent.signature,
			storedContent.ciphertextWithNonce = nil, nil, nil
		storedContentRWMutex.Unlock()
	} else {
		storedContentRWMutex.RLock()
		encryptSkID, signature, ciphertextWithNonce =
			storedContent.encryptSkID, storedContent.signature,
			storedContent.ciphertextWithNonce
		storedContentRWMutex.RUnlock()
	}

	h3 := auth3get(conf, clientVersion, h2, encryptSkID, signature)
	writer.Write(h3)
	ciphertextWithNonceLen := uint64(len(ciphertextWithNonce))
	binary.Write(writer, binary.LittleEndian, ciphertextWithNonceLen)
	writer.Write(encryptSkID)
	writer.Write(signature)
	writer.Write(ciphertextWithNonce)
	if err := writer.Flush(); err != nil {
		log.Print(err)
		return
	}
}

func storeOperation(conf Conf, h1 []byte, reader *bufio.Reader, writer *bufio.Writer,
	clientVersion byte) {
	rbuf := make([]byte, 112)
	if _, err := io.ReadFull(reader, rbuf); err != nil {
		log.Print(err)
		return
	}
	h2 := rbuf[0:32]
	ciphertextWithNonceLen := binary.LittleEndian.Uint64(rbuf[32:40])
	if conf.MaxLen > 0 && ciphertextWithNonceLen > conf.MaxLen {
		fmt.Printf("%v bytes requested to be stored, but limit set to %v bytes (%v Mb)\n",
			ciphertextWithNonceLen, conf.MaxLen, conf.MaxLen/(1024*1024))
		return
	}
	encryptedSkID := rbuf[40:48]
	signature := rbuf[48:112]
	opcode := byte('S')
	wh2 := auth2store(conf, Version, h1, opcode, signature)
	if subtle.ConstantTimeCompare(wh2, h2) != 1 {
		return
	}
	ciphertextWithNonce := make([]byte, ciphertextWithNonceLen)
	if _, err := io.ReadFull(reader, ciphertextWithNonce); err != nil {
		log.Print(err)
		return
	}
	if ed25519.Verify(conf.SignPk, ciphertextWithNonce, signature) != true {
		return
	}
	h3 := auth3store(conf, clientVersion, h2)

	storedContentRWMutex.Lock()
	storedContent.encryptSkID = encryptedSkID
	storedContent.signature = signature
	storedContent.ciphertextWithNonce = ciphertextWithNonce
	storedContentRWMutex.Unlock()

	writer.Write(h3)
	if err := writer.Flush(); err != nil {
		log.Print(err)
		return
	}
}

func handleClient(conf Conf, conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	rbuf := make([]byte, 65)
	if _, err := io.ReadFull(reader, rbuf); err != nil {
		log.Print(err)
		return
	}
	clientVersion := rbuf[0]
	if clientVersion < 2 || clientVersion > 4 {
		log.Print("Unsupported client version - Please run the same version on the server and on the client")
		return
	}
	r := rbuf[1:33]
	h0 := rbuf[33:65]
	wh0 := auth0(conf, clientVersion, r)
	if subtle.ConstantTimeCompare(wh0, h0) != 1 {
		return
	}
	r2 := make([]byte, 32)
	if _, err := rand.Read(r); err != nil {
		log.Fatal(err)
	}
	h1 := auth1(conf, clientVersion, h0, r2)
	writer := bufio.NewWriter(conn)
	writer.Write([]byte{clientVersion})
	if clientVersion > 3 {
		writer.Write(r2)
	}
	writer.Write(h1)
	if err := writer.Flush(); err != nil {
		log.Print(err)
		return
	}
	opcode, err := reader.ReadByte()
	if err != nil {
		return
	}
	switch opcode {
	case byte('G'):
		getOperation(conf, h1, reader, writer, clientVersion, false)
	case byte('M'):
		getOperation(conf, h1, reader, writer, clientVersion, true)
	case byte('S'):
		storeOperation(conf, h1, reader, writer, clientVersion)
	}
}

// ServerMain - run a server
func ServerMain(conf Conf) {
	listen, err := net.Listen("tcp", conf.Listen)
	if err != nil {
		log.Fatal(err)
	}
	defer listen.Close()
	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleClient(conf, conn)
	}
}
