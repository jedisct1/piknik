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
const DefaultClientVersion = byte(6)

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

	conf, reader, writer := client.conf, client.reader, client.writer

	var contentWithEncryptSkIDAndNonceBuf bytes.Buffer
	contentWithEncryptSkIDAndNonceBuf.Grow(8 + 24 + bytes.MinRead)

	contentWithEncryptSkIDAndNonceBuf.Write(conf.EncryptSkID)

	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatal(err)
	}
	contentWithEncryptSkIDAndNonceBuf.Write(nonce)

	_, err := contentWithEncryptSkIDAndNonceBuf.ReadFrom(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	contentWithEncryptSkIDAndNonce := contentWithEncryptSkIDAndNonceBuf.Bytes()

	cipher, err := chacha20.NewCipher(conf.EncryptSk, nonce)
	if err != nil {
		log.Fatal(err)
	}
	opcode := byte('S')
	cipher.XORKeyStream(contentWithEncryptSkIDAndNonce[8+24:], contentWithEncryptSkIDAndNonce[8+24:])
	signature := ed25519.Sign(conf.SignSk, contentWithEncryptSkIDAndNonce)

	client.conn.SetDeadline(time.Now().Add(conf.DataTimeout))
	h2 := auth2store(conf, client.version, h1, opcode, ts, signature)
	writer.WriteByte(opcode)
	writer.Write(h2)
	ciphertextWithEncryptSkIDAndNonceLen := uint64(len(contentWithEncryptSkIDAndNonce))
	binary.Write(writer, binary.LittleEndian, ciphertextWithEncryptSkIDAndNonceLen)
	writer.Write(ts)
	writer.Write(signature)
	writer.Write(contentWithEncryptSkIDAndNonce)
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
	rbuf := make([]byte, 112)
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
	ciphertextWithEncryptSkIDAndNonceLen := binary.LittleEndian.Uint64(rbuf[32:40])
	ts := rbuf[40:48]
	signature := rbuf[48:112]
	wh3 := auth3get(conf, client.version, h2, ts, signature)
	if subtle.ConstantTimeCompare(wh3, h3) != 1 {
		log.Fatal("Incorrect authentication code")
	}
	elapsed := time.Since(time.Unix(int64(binary.LittleEndian.Uint64(ts)), 0))
	if elapsed >= conf.TTL {
		log.Fatal("Clipboard content is too old")
	}
	if ciphertextWithEncryptSkIDAndNonceLen < 8+24 {
		log.Fatal("Clipboard content is too short")
	}
	ciphertextWithEncryptSkIDAndNonce := make([]byte, ciphertextWithEncryptSkIDAndNonceLen)
	client.conn.SetDeadline(time.Now().Add(conf.DataTimeout))
	if _, err := io.ReadFull(reader, ciphertextWithEncryptSkIDAndNonce); err != nil {
		if err == io.ErrUnexpectedEOF {
			log.Fatal("The server may be running an incompatible version")
		} else {
			log.Fatal(err)
		}
	}
	encryptSkID := ciphertextWithEncryptSkIDAndNonce[0:8]
	if bytes.Equal(conf.EncryptSkID, encryptSkID) == false {
		wEncryptSkIDStr := binary.LittleEndian.Uint64(conf.EncryptSkID)
		encryptSkIDStr := binary.LittleEndian.Uint64(encryptSkID)
		log.Fatal(fmt.Sprintf("Configured key ID is %v but content was encrypted using key ID %v",
			wEncryptSkIDStr, encryptSkIDStr))
	}
	if ed25519.Verify(conf.SignPk, ciphertextWithEncryptSkIDAndNonce, signature) != true {
		log.Fatal("Signature doesn't verify")
	}
	nonce := ciphertextWithEncryptSkIDAndNonce[8:32]
	cipher, err := chacha20.NewCipher(conf.EncryptSk, nonce)
	if err != nil {
		log.Fatal(err)
	}
	content := ciphertextWithEncryptSkIDAndNonce[32:]
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
