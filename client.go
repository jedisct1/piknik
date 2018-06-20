package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/yawning/chacha20"
	"golang.org/x/crypto/ed25519"
)

// DefaultClientVersion - Default client version
const DefaultClientVersion = byte(5)

// Client - Client data
type Client struct {
	conf    Conf
	conn    net.Conn
	reader  *bufio.Reader
	writer  *bufio.Writer
	version byte
}

func (client *Client) copyOperation(h1 []byte) {
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64(time.Now().Unix()))

	var contentWithNonceBuf bytes.Buffer
	contentWithNonceBuf.Grow(24 + bytes.MinRead)

	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatal(err)
	}
	contentWithNonceBuf.Write(nonce)

	conf, reader, writer := client.conf, client.reader, client.writer
	_, err := contentWithNonceBuf.ReadFrom(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	contentWithNonce := contentWithNonceBuf.Bytes()

	cipher, err := chacha20.NewCipher(conf.EncryptSk, nonce)
	if err != nil {
		log.Fatal(err)
	}
	opcode := byte('S')
	cipher.XORKeyStream(contentWithNonce[24:], contentWithNonce[24:])
	signature := ed25519.Sign(conf.SignSk, contentWithNonce)

	client.conn.SetDeadline(time.Now().Add(conf.DataTimeout))
	h2 := auth2store(conf, client.version, h1, opcode, conf.EncryptSkID, ts, signature)
	writer.WriteByte(opcode)
	writer.Write(h2)
	ciphertextWithNonceLen := uint64(len(contentWithNonce))
	binary.Write(writer, binary.LittleEndian, ciphertextWithNonceLen)
	writer.Write(conf.EncryptSkID)
	writer.Write(ts)
	writer.Write(signature)
	writer.Write(contentWithNonce)
	if err = writer.Flush(); err != nil {
		log.Fatal(err)
	}
	rbuf := make([]byte, 32)
	if _, err = io.ReadFull(reader, rbuf); err != nil {
		if err == io.ErrUnexpectedEOF {
			log.Fatal("The server may be running an incompatible version")
		} else {
			log.Fatal(err)
		}
	}
	h3 := rbuf
	wh3 := auth3store(conf, h2)
	if subtle.ConstantTimeCompare(wh3, h3) != 1 {
		log.Fatal("Incorrect authentication code")
	}
	if IsTerminal(int(syscall.Stderr)) {
		os.Stderr.WriteString("Sent\n")
	}
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
	rbuf := make([]byte, 120)
	if nbread, err := io.ReadFull(reader, rbuf); err != nil {
		if err == io.ErrUnexpectedEOF {
			if nbread < 80 {
				log.Fatal("The clipboard might be empty")
			} else {
				log.Fatal("The server may be running an incompatible version")
			}
		} else {
			log.Fatal(err)
		}
	}
	h3 := rbuf[0:32]
	ciphertextWithNonceLen := binary.LittleEndian.Uint64(rbuf[32:40])
	encryptSkID := rbuf[40:48]
	ts := rbuf[48:56]
	signature := rbuf[56:120]
	wh3 := auth3get(conf, client.version, h2, encryptSkID, ts, signature)
	if subtle.ConstantTimeCompare(wh3, h3) != 1 {
		log.Fatal("Incorrect authentication code")
	}
	elapsed := time.Since(time.Unix(int64(binary.LittleEndian.Uint64(ts)), 0))
	if elapsed >= conf.TTL {
		log.Fatal("Clipboard content is too old")
	}
	if bytes.Equal(conf.EncryptSkID, encryptSkID) == false {
		wEncryptSkIDStr := binary.LittleEndian.Uint64(conf.EncryptSkID)
		encryptSkIDStr := binary.LittleEndian.Uint64(encryptSkID)
		log.Fatal(fmt.Sprintf("Configured key ID is %v but content was encrypted using key ID %v",
			wEncryptSkIDStr, encryptSkIDStr))
	}
	ciphertextWithNonce := make([]byte, ciphertextWithNonceLen)

	client.conn.SetDeadline(time.Now().Add(conf.DataTimeout))
	if _, err := io.ReadFull(reader, ciphertextWithNonce); err != nil {
		if err == io.ErrUnexpectedEOF {
			log.Fatal("The server may be running an incompatible version")
		} else {
			log.Fatal(err)
		}
	}
	if ed25519.Verify(conf.SignPk, ciphertextWithNonce, signature) != true {
		log.Fatal("Signature doesn't verify")
	}
	nonce := ciphertextWithNonce[0:24]
	cipher, err := chacha20.NewCipher(conf.EncryptSk, nonce)
	if err != nil {
		log.Fatal(err)
	}
	content := ciphertextWithNonce[24:]
	cipher.XORKeyStream(content, content)
	binary.Write(os.Stdout, binary.LittleEndian, content)
}

// RunClient - Process a client query
func RunClient(conf Conf, isCopy bool, isMove bool) {
	conn, err := net.DialTimeout("tcp", conf.Connect, conf.Timeout)
	if err != nil {
		log.Fatal(fmt.Sprintf("Unable to connect to %v - Is a Piknik server running on that host?",
			conf.Connect))
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(conf.Timeout))
	reader, writer := bufio.NewReader(conn), bufio.NewWriter(conn)
	client := Client{
		conf:    conf,
		conn:    conn,
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
	if nbread, err := io.ReadFull(reader, rbuf); err != nil {
		if nbread < 2 {
			log.Fatal("The server rejected the connection - Check that it is running the same Piknik version or retry later")
		} else {
			log.Fatal("The server doesn't support this protocol")
		}
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
