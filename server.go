package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ed25519"
)

type ClientConnection struct {
	conf          Conf
	conn          net.Conn
	reader        *bufio.Reader
	writer        *bufio.Writer
	clientVersion byte
}

type StoredContent struct {
	sync.RWMutex

	ts                                []byte
	signature                         []byte
	ciphertextWithEncryptSkIDAndNonce []byte
}

type subscriber struct {
	ch   chan []byte
	done chan struct{}
}

type StreamHub struct {
	mu         sync.Mutex
	pushActive bool
	pullers    map[uint64]*subscriber
	nextID     uint64
	waitCh     chan struct{}
}

var (
	storedContent  StoredContent
	trustedClients TrustedClients
	clientsCount   = uint64(0)
	streamHub      StreamHub
)

func initStreamHub() {
	streamHub.pullers = make(map[uint64]*subscriber)
	streamHub.waitCh = make(chan struct{})
}

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

	var ts, signature, ciphertextWithEncryptSkIDAndNonce []byte
	if isMove {
		storedContent.Lock()
		ts, signature, ciphertextWithEncryptSkIDAndNonce = storedContent.ts, storedContent.signature, storedContent.ciphertextWithEncryptSkIDAndNonce
		storedContent.ts, storedContent.signature,
			storedContent.ciphertextWithEncryptSkIDAndNonce = nil, nil, nil
		storedContent.Unlock()
	} else {
		storedContent.RLock()
		ts, signature, ciphertextWithEncryptSkIDAndNonce = storedContent.ts, storedContent.signature,
			storedContent.ciphertextWithEncryptSkIDAndNonce
		storedContent.RUnlock()
	}

	cnx.conn.SetDeadline(time.Now().Add(conf.DataTimeout))
	h3 := auth3get(conf, cnx.clientVersion, h2, ts, signature)
	writer.Write(h3)
	ciphertextWithEncryptSkIDAndNonceLen := uint64(len(ciphertextWithEncryptSkIDAndNonce))
	binary.Write(writer, binary.LittleEndian, ciphertextWithEncryptSkIDAndNonceLen)
	writer.Write(ts)
	writer.Write(signature)
	writer.Write(ciphertextWithEncryptSkIDAndNonce)
	if err := writer.Flush(); err != nil {
		log.Print(err)
		return
	}
}

func (cnx *ClientConnection) storeOperation(h1 []byte) {
	conf, reader, writer := cnx.conf, cnx.reader, cnx.writer
	rbuf := make([]byte, 112)
	if _, err := io.ReadFull(reader, rbuf); err != nil {
		log.Print(err)
		return
	}
	h2 := rbuf[0:32]
	ciphertextWithEncryptSkIDAndNonceLen := binary.LittleEndian.Uint64(rbuf[32:40])
	if ciphertextWithEncryptSkIDAndNonceLen < 8+24 {
		log.Printf("Short encrypted message (only %v bytes)\n", ciphertextWithEncryptSkIDAndNonceLen)
		return
	}
	if conf.MaxLen > 0 && ciphertextWithEncryptSkIDAndNonceLen > conf.MaxLen {
		log.Printf("%v bytes requested to be stored, but limit set to %v bytes (%v Mb)\n",
			ciphertextWithEncryptSkIDAndNonceLen, conf.MaxLen, conf.MaxLen/(1024*1024))
		return
	}
	var ts, signature []byte
	ts = rbuf[40:48]
	signature = rbuf[48:112]
	opcode := byte('S')

	wh2 := auth2store(conf, cnx.clientVersion, h1, opcode, ts, signature)
	if subtle.ConstantTimeCompare(wh2, h2) != 1 {
		return
	}
	ciphertextWithEncryptSkIDAndNonce := make([]byte, ciphertextWithEncryptSkIDAndNonceLen)

	cnx.conn.SetDeadline(time.Now().Add(conf.DataTimeout))
	if _, err := io.ReadFull(reader, ciphertextWithEncryptSkIDAndNonce); err != nil {
		log.Print(err)
		return
	}
	if !ed25519.Verify(conf.SignPk, ciphertextWithEncryptSkIDAndNonce, signature) {
		return
	}
	h3 := auth3store(conf, h2)

	storedContent.Lock()
	storedContent.ts = ts
	storedContent.signature = signature
	storedContent.ciphertextWithEncryptSkIDAndNonce = ciphertextWithEncryptSkIDAndNonce
	storedContent.Unlock()

	writer.Write(h3)
	if err := writer.Flush(); err != nil {
		log.Print(err)
		return
	}
}

func (cnx *ClientConnection) pullStreamOperation(h1 []byte) {
	conf, reader, writer := cnx.conf, cnx.reader, cnx.writer
	rbuf := make([]byte, 32)
	if _, err := io.ReadFull(reader, rbuf); err != nil {
		log.Print(err)
		return
	}
	h2 := rbuf
	opcode := byte('L')
	wh2 := auth2get(conf, cnx.clientVersion, h1, opcode)
	if subtle.ConstantTimeCompare(wh2, h2) != 1 {
		return
	}

	streamHub.mu.Lock()
	if streamHub.pushActive {
		streamHub.mu.Unlock()
		log.Print("Stream pull rejected: stream already active")
		return
	}
	if uint(len(streamHub.pullers)) >= conf.MaxWaitingPullers {
		streamHub.mu.Unlock()
		log.Print("Stream pull rejected: too many waiting pullers")
		return
	}
	sub := &subscriber{
		ch:   make(chan []byte, 64),
		done: make(chan struct{}),
	}
	id := streamHub.nextID
	streamHub.nextID++
	streamHub.pullers[id] = sub
	waitCh := streamHub.waitCh
	streamHub.mu.Unlock()

	defer func() {
		streamHub.mu.Lock()
		delete(streamHub.pullers, id)
		streamHub.mu.Unlock()
		close(sub.done)
	}()

	_ = reader
	waitTimeout := conf.TTL
	if waitTimeout < time.Hour {
		waitTimeout = time.Hour
	}
	cnx.conn.SetDeadline(time.Now().Add(waitTimeout))

	select {
	case <-waitCh:
	case <-sub.done:
		return
	case <-time.After(waitTimeout):
		log.Printf("Puller %v: wait timeout expired", id)
		return
	}

	cnx.conn.SetDeadline(time.Now().Add(conf.DataTimeout))
	for frame := range sub.ch {
		if _, err := writer.Write(frame); err != nil {
			log.Printf("Puller %v write error: %v", id, err)
			return
		}
		if err := writer.Flush(); err != nil {
			log.Printf("Puller %v flush error: %v", id, err)
			return
		}
		cnx.conn.SetDeadline(time.Now().Add(conf.DataTimeout))
	}
}

func (cnx *ClientConnection) pushStreamOperation(h1 []byte) {
	conf, reader, writer := cnx.conf, cnx.reader, cnx.writer
	rbuf := make([]byte, 32)
	if _, err := io.ReadFull(reader, rbuf); err != nil {
		log.Print(err)
		return
	}
	h2 := rbuf
	opcode := byte('P')
	wh2 := auth2get(conf, cnx.clientVersion, h1, opcode)
	if subtle.ConstantTimeCompare(wh2, h2) != 1 {
		return
	}

	streamHub.mu.Lock()
	if streamHub.pushActive {
		streamHub.mu.Unlock()
		log.Print("Stream push rejected: another push already active")
		writer.WriteByte(0x02)
		writer.Flush()
		return
	}
	streamHub.pushActive = true

	snapshot := make(map[uint64]*subscriber)
	for id, sub := range streamHub.pullers {
		snapshot[id] = sub
	}

	if len(snapshot) == 0 {
		streamHub.pushActive = false
		streamHub.mu.Unlock()
		log.Print("Stream push rejected: no pullers waiting")
		writer.WriteByte(0x00)
		writer.Flush()
		return
	}

	oldWaitCh := streamHub.waitCh
	streamHub.waitCh = make(chan struct{})
	streamHub.mu.Unlock()

	close(oldWaitCh)

	defer func() {
		for _, sub := range snapshot {
			close(sub.ch)
		}
		streamHub.mu.Lock()
		streamHub.pushActive = false
		streamHub.mu.Unlock()
	}()

	writer.WriteByte(0x01)
	if err := writer.Flush(); err != nil {
		log.Print("Stream push: failed to send accept status: ", err)
		return
	}

	relay := func(frame []byte) {
		for id, sub := range snapshot {
			select {
			case sub.ch <- frame:
			case <-sub.done:
				delete(snapshot, id)
			}
		}
	}

	header := make([]byte, 32)
	cnx.conn.SetDeadline(time.Now().Add(conf.DataTimeout))
	if _, err := io.ReadFull(reader, header); err != nil {
		log.Print("Stream push: failed to read header: ", err)
		return
	}
	relay(header)

	var streamStart time.Time
	if conf.MaxStreamDuration > 0 {
		streamStart = time.Now()
	}
	var totalBytes uint64

	for {
		var chunkLen uint32
		cnx.conn.SetDeadline(time.Now().Add(conf.DataTimeout))
		if err := binary.Read(reader, binary.LittleEndian, &chunkLen); err != nil {
			log.Print("Stream push: failed to read chunk length: ", err)
			return
		}

		lenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBuf, chunkLen)

		if chunkLen == 0 {
			sig := make([]byte, 64)
			if _, err := io.ReadFull(reader, sig); err != nil {
				log.Print("Stream push: failed to read signature: ", err)
				return
			}
			relay(append(lenBuf, sig...))
			return
		}

		if chunkLen > MaxChunk {
			log.Printf("Stream push: chunk too large (%v > %v)", chunkLen, MaxChunk)
			return
		}

		sealedLen := uint32(chunkLen) + 16
		totalBytes += uint64(sealedLen)
		if conf.MaxStreamBytes > 0 && totalBytes > conf.MaxStreamBytes {
			log.Print("Stream push: exceeded MaxStreamBytes")
			return
		}
		if conf.MaxStreamDuration > 0 && time.Since(streamStart) > conf.MaxStreamDuration {
			log.Print("Stream push: exceeded MaxStreamDuration")
			return
		}

		sealed := make([]byte, sealedLen)
		cnx.conn.SetDeadline(time.Now().Add(conf.DataTimeout))
		if _, err := io.ReadFull(reader, sealed); err != nil {
			log.Print("Stream push: failed to read chunk data: ", err)
			return
		}

		frame := make([]byte, 4+len(sealed))
		copy(frame, lenBuf)
		copy(frame[4:], sealed)
		relay(frame)
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
		return
	}
	cnx.clientVersion = rbuf[0]
	if cnx.clientVersion != 6 && cnx.clientVersion != 7 {
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
	if _, err := rand.Read(r2); err != nil {
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
	case byte('P'):
		if cnx.clientVersion < 7 {
			log.Print("Stream push requires protocol version 7")
			return
		}
		cnx.pushStreamOperation(h1)
	case byte('L'):
		if cnx.clientVersion < 7 {
			log.Print("Stream pull requires protocol version 7")
			return
		}
		cnx.pullStreamOperation(h1)
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
	handleClientConnection(conf, conn)
	atomic.AddUint64(&clientsCount, ^uint64(0))
}

func maybeAcceptClient(conf Conf, conn net.Conn) {
	conn.SetDeadline(time.Now().Add(conf.Timeout))
	remoteIP := conn.RemoteAddr().(*net.TCPAddr).IP
	for {
		count := atomic.LoadUint64(&clientsCount)
		if count >= conf.MaxClients-conf.TrustedIPCount && !isIPTrusted(conf, remoteIP) {
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
	go acceptClient(conf, conn)
}

func RunServer(conf Conf) {
	initStreamHub()
	go handleSignals()
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
		maybeAcceptClient(conf, conn)
	}
}
