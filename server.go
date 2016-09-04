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
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ed25519"
)

// ClientConnection - A client connection
type ClientConnection struct {
	conf          Conf
	conn          net.Conn
	reader        *bufio.Reader
	writer        *bufio.Writer
	clientVersion byte
}

// StoredContent - Paste buffer
type StoredContent struct {
	sync.RWMutex

	encryptSkID         []byte
	ts                  []byte
	signature           []byte
	ciphertextWithNonce []byte
}

var storedContent StoredContent
var trustedClients TrustedClients
var clientsCount = uint64(0)

func (cnx *ClientConnection) getOperation(h1 []byte, isMove bool) {
	conf, reader, writer := cnx.conf, cnx.reader, cnx.writer
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
	wh2 := auth2get(conf, cnx.clientVersion, h1, opcode)
	if subtle.ConstantTimeCompare(wh2, h2) != 1 {
		return
	}

	var encryptSkID, ts, signature, ciphertextWithNonce []byte
	if isMove {
		storedContent.Lock()
		encryptSkID, ts, signature, ciphertextWithNonce =
			storedContent.encryptSkID, storedContent.ts,
			storedContent.signature, storedContent.ciphertextWithNonce
		storedContent.encryptSkID, storedContent.ts, storedContent.signature,
			storedContent.ciphertextWithNonce = nil, nil, nil, nil
		storedContent.Unlock()
	} else {
		storedContent.RLock()
		encryptSkID, ts, signature, ciphertextWithNonce =
			storedContent.encryptSkID, storedContent.ts, storedContent.signature,
			storedContent.ciphertextWithNonce
		storedContent.RUnlock()
	}

	cnx.conn.SetDeadline(time.Now().Add(conf.DataTimeout))
	h3 := auth3get(conf, cnx.clientVersion, h2, encryptSkID, ts, signature)
	writer.Write(h3)
	ciphertextWithNonceLen := uint64(len(ciphertextWithNonce))
	binary.Write(writer, binary.LittleEndian, ciphertextWithNonceLen)
	writer.Write(encryptSkID)
	if cnx.clientVersion >= 5 {
		writer.Write(ts)
	}
	writer.Write(signature)
	writer.Write(ciphertextWithNonce)
	if err := writer.Flush(); err != nil {
		log.Print(err)
		return
	}
}

func (cnx *ClientConnection) storeOperation(h1 []byte) {
	conf, reader, writer := cnx.conf, cnx.reader, cnx.writer
	var rbuf []byte
	if cnx.clientVersion < 5 {
		rbuf = make([]byte, 112)
	} else {
		rbuf = make([]byte, 120)
	}
	if _, err := io.ReadFull(reader, rbuf); err != nil {
		log.Print(err)
		return
	}
	h2 := rbuf[0:32]
	ciphertextWithNonceLen := binary.LittleEndian.Uint64(rbuf[32:40])
	if conf.MaxLen > 0 && ciphertextWithNonceLen > conf.MaxLen {
		log.Printf("%v bytes requested to be stored, but limit set to %v bytes (%v Mb)\n",
			ciphertextWithNonceLen, conf.MaxLen, conf.MaxLen/(1024*1024))
		return
	}
	encryptSkID := rbuf[40:48]
	var ts, signature []byte
	if cnx.clientVersion < 5 {
		ts = make([]byte, 8)
		binary.LittleEndian.PutUint64(ts, uint64(time.Now().Unix()))
		signature = rbuf[48:112]
	} else {
		ts = rbuf[48:56]
		signature = rbuf[56:120]
	}
	opcode := byte('S')

	wh2 := auth2store(conf, cnx.clientVersion, h1, opcode, encryptSkID, ts, signature)
	if subtle.ConstantTimeCompare(wh2, h2) != 1 {
		return
	}
	ciphertextWithNonce := make([]byte, ciphertextWithNonceLen)

	cnx.conn.SetDeadline(time.Now().Add(conf.DataTimeout))
	if _, err := io.ReadFull(reader, ciphertextWithNonce); err != nil {
		log.Print(err)
		return
	}
	if ed25519.Verify(conf.SignPk, ciphertextWithNonce, signature) != true {
		return
	}
	h3 := auth3store(conf, cnx.clientVersion, h2)

	storedContent.Lock()
	storedContent.encryptSkID = encryptSkID
	storedContent.ts = ts
	storedContent.signature = signature
	storedContent.ciphertextWithNonce = ciphertextWithNonce
	storedContent.Unlock()

	writer.Write(h3)
	if err := writer.Flush(); err != nil {
		log.Print(err)
		return
	}
}

func handleClientConnection(conf Conf, conn net.Conn) {
	defer conn.Close()
	reader, writer := bufio.NewReader(conn), bufio.NewWriter(conn)
	cnx := ClientConnection{
		conf:   conf,
		conn:   conn,
		reader: reader,
		writer: writer,
	}
	rbuf := make([]byte, 65)
	if _, err := io.ReadFull(reader, rbuf); err != nil {
		log.Print(err)
		return
	}
	cnx.clientVersion = rbuf[0]
	if cnx.clientVersion < 4 || cnx.clientVersion > 5 {
		log.Print("Unsupported client version - Please run the same version on the server and on the client")
		return
	}
	r := rbuf[1:33]
	h0 := rbuf[33:65]
	wh0 := auth0(conf, cnx.clientVersion, r)
	if subtle.ConstantTimeCompare(wh0, h0) != 1 {
		return
	}
	r2 := make([]byte, 32)
	if _, err := rand.Read(r); err != nil {
		log.Fatal(err)
	}
	h1 := auth1(conf, cnx.clientVersion, h0, r2)
	writer.Write([]byte{cnx.clientVersion})
	writer.Write(r2)
	writer.Write(h1)
	if err := writer.Flush(); err != nil {
		log.Print(err)
		return
	}
	remoteIP := cnx.conn.RemoteAddr().(*net.TCPAddr).IP
	addToTrustedIPs(conf, remoteIP)
	opcode, err := reader.ReadByte()
	if err != nil {
		return
	}
	switch opcode {
	case byte('G'):
		cnx.getOperation(h1, false)
	case byte('M'):
		cnx.getOperation(h1, true)
	case byte('S'):
		cnx.storeOperation(h1)
	}
}

type TrustedClients struct {
	sync.RWMutex

	ips []net.IP
}

func addToTrustedIPs(conf Conf, ip net.IP) {
	trustedClients.Lock()
	if uint64(len(trustedClients.ips)) >= conf.TrustedIPCount {
		trustedClients.ips = append(trustedClients.ips[1:], ip)
	} else {
		trustedClients.ips = append(trustedClients.ips, ip)
	}
	trustedClients.Unlock()
}

func isIPTrusted(conf Conf, ip net.IP) bool {
	trustedClients.RLock()
	defer trustedClients.RUnlock()
	if len(trustedClients.ips) == 0 {
		return true
	}
	for _, foundIP := range trustedClients.ips {
		if foundIP.Equal(ip) {
			return true
		}
	}
	return false
}

func acceptClient(conf Conf, conn net.Conn) {
	conn.SetDeadline(time.Now().Add(conf.Timeout))
	remoteIP := conn.RemoteAddr().(*net.TCPAddr).IP
	for {
		count := atomic.LoadUint64(&clientsCount)
		if count >= conf.MaxClients-conf.TrustedIPCount && isIPTrusted(conf, remoteIP) == false {
			conn.Close()
			return
		}
		if count >= conf.MaxClients {
			conn.Close()
			return
		} else if atomic.CompareAndSwapUint64(&clientsCount, count, count+1) {
			break
		}
	}
	handleClientConnection(conf, conn)
	atomic.AddUint64(&clientsCount, ^uint64(0))
}

// RunServer - run a server
func RunServer(conf Conf) {
	go handleSignals()

	listen, err := net.Listen("tcp", conf.Listen)
	if err != nil {
		log.Fatal(err)
	}
	defer listen.Close()

	// start 2 workers per cpu
	conns := make(chan net.Conn, runtime.NumCPU() * 4)
	defer close(conns)
	for i := 0; i <= runtime.NumCPU() * 2; i++ {
		go func() {
			for conn := range conns {
				acceptClient(conf, conn)
			}
		}()
	}

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Fatal(err)
		}
		conns <-conn
	}

}

func handleSignals() {
        signals := make(chan os.Signal, 1)
        signal.Notify(signals, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGUSR1)

	for {
		select {
		case signal, ok := <-signals:
			if !ok { break }

			switch(signal) {
			case syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM:
				os.Exit(2)
			case syscall.SIGUSR1:
				if len(storedContent.ciphertextWithNonce) > 0 {
					fmt.Printf("%v: some data is stored\n", os.Args[0])
				} else {
					fmt.Printf("%v: no data stored yet\n", os.Args[0])
				}
			}
		}
	}
}
