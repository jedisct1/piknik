package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"runtime"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/codahale/blake2"
	"github.com/mitchellh/go-homedir"
	"github.com/yawning/chacha20"
	"golang.org/x/crypto/ed25519"
)

const domainStr = "PK"

type tomlConfig struct {
	Listen    string
	Connect   string
	Psk       string
	EncryptSk string
	SignSk    string
	SignPk    string
}

// Conf - Shared config
type Conf struct {
	Listen    string
	Connect   string
	Psk       []byte
	EncryptSk []byte
	SignSk    []byte
	SignPk    []byte
}

// StoredContent - Paste buffer
type StoredContent struct {
	signature           []byte
	ciphertextWithNonce []byte
}

var storedContent StoredContent
var storedContentRWMutex sync.RWMutex

func client(conf Conf, isPut bool) {
	conn, err := net.Dial("tcp", conf.Connect)
	if err != nil {
		log.Panic(err)
	}
	r := make([]byte, 32)
	if _, err = rand.Read(r); err != nil {
		log.Fatal(err)
	}
	hf0 := blake2.New(&blake2.Config{
		Key:      conf.Psk,
		Personal: []byte(domainStr),
		Size:     32,
		Salt:     []byte{0},
	})
	version := byte(1)
	hf0.Write([]byte{version})
	hf0.Write(r)
	h0 := hf0.Sum(nil)
	writer := bufio.NewWriter(conn)
	writer.Write([]byte{version})
	writer.Write(r)
	writer.Write(h0)
	if err := writer.Flush(); err != nil {
		log.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	rbuf := make([]byte, 33)
	if _, err = io.ReadFull(reader, rbuf); err != nil {
		return
	}
	if rbuf[0] != version {
		return
	}
	h1 := rbuf[1:33]
	hf1 := blake2.New(&blake2.Config{
		Key:      conf.Psk,
		Personal: []byte(domainStr),
		Size:     32,
		Salt:     []byte{1},
	})
	hf1.Write([]byte{version})
	hf1.Write(h0)
	wh1 := hf1.Sum(nil)
	if subtle.ConstantTimeCompare(wh1, h1) != 1 {
		return
	}

	if isPut {
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
		ciphertextWithNonce := make([]byte, 24+len(content))
		copy(ciphertextWithNonce, nonce)
		ciphertext := ciphertextWithNonce[24:]
		cipher.XORKeyStream(ciphertext, content)

		signature := ed25519.Sign(conf.SignSk, ciphertextWithNonce)

		hf2 := blake2.New(&blake2.Config{
			Key:      conf.Psk,
			Personal: []byte(domainStr),
			Size:     32,
			Salt:     []byte{2},
		})
		hf2.Write(h1)
		hf2.Write(signature)
		h2 := hf2.Sum(nil)

		writer.WriteByte(byte('S'))
		writer.Write(h2)
		ciphertextWithNonceLen := uint64(len(ciphertextWithNonce))
		binary.Write(writer, binary.LittleEndian, ciphertextWithNonceLen)
		writer.Write(signature)
		writer.Write(ciphertextWithNonce)
		if err := writer.Flush(); err != nil {
			log.Fatal(err)
		}

		rbuf = make([]byte, 32)
		if _, err = io.ReadFull(reader, rbuf); err != nil {
			return
		}
		h3 := rbuf
		hf3 := blake2.New(&blake2.Config{
			Key:      conf.Psk,
			Personal: []byte(domainStr),
			Size:     32,
			Salt:     []byte{3},
		})
		hf3.Write(h2)
		wh3 := hf3.Sum(nil)
		if subtle.ConstantTimeCompare(wh3, h3) != 1 {
			return
		}
		fmt.Println("Sent and ACK'd by the server")
	} else { // !isPut
		hf2 := blake2.New(&blake2.Config{
			Key:      conf.Psk,
			Personal: []byte(domainStr),
			Size:     32,
			Salt:     []byte{2},
		})
		hf2.Write(h1)
		h2 := hf2.Sum(nil)
		writer.WriteByte(byte('G'))
		writer.Write(h2)
		if err := writer.Flush(); err != nil {
			log.Fatal(err)
		}

		rbuf := make([]byte, 104)
		if _, err := io.ReadFull(reader, rbuf); err != nil {
			return
		}
		h3 := rbuf[0:32]
		ciphertextWithNonceLen := binary.LittleEndian.Uint64(rbuf[32:40])
		signature := rbuf[40:104]
		hf3 := blake2.New(&blake2.Config{
			Key:      conf.Psk,
			Personal: []byte(domainStr),
			Size:     32,
			Salt:     []byte{3},
		})
		hf3.Write(h2)
		hf3.Write(signature)
		wh3 := hf3.Sum(nil)
		if subtle.ConstantTimeCompare(wh3, h3) != 1 {
			return
		}
		ciphertextWithNonce := make([]byte, ciphertextWithNonceLen)
		if _, err := io.ReadFull(reader, ciphertextWithNonce); err != nil {
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
}

func handleClient(conf Conf, conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	rbuf := make([]byte, 65)
	if _, err := io.ReadFull(reader, rbuf); err != nil {
		return
	}
	version := rbuf[0]
	if version != 1 {
		return
	}
	r := rbuf[1:33]
	h0 := rbuf[33:65]
	hf0 := blake2.New(&blake2.Config{
		Key:      conf.Psk,
		Personal: []byte(domainStr),
		Size:     32,
		Salt:     []byte{0},
	})
	hf0.Write([]byte{version})
	hf0.Write(r)
	wh0 := hf0.Sum(nil)
	if subtle.ConstantTimeCompare(wh0, h0) != 1 {
		return
	}
	hf1 := blake2.New(&blake2.Config{
		Key:      conf.Psk,
		Personal: []byte(domainStr),
		Size:     32,
		Salt:     []byte{1},
	})
	hf1.Write([]byte{version})
	hf1.Write(h0)
	h1 := hf1.Sum(nil)
	writer := bufio.NewWriter(conn)
	writer.Write([]byte{version})
	writer.Write(h1)
	if err := writer.Flush(); err != nil {
		return
	}

	operation, err := reader.ReadByte()
	if err != nil {
		return
	}
	if operation == byte('S') {
		rbuf := make([]byte, 104)
		if _, err := io.ReadFull(reader, rbuf); err != nil {
			return
		}
		h2 := rbuf[0:32]
		ciphertextWithNonceLen := binary.LittleEndian.Uint64(rbuf[32:40])
		signature := rbuf[40:104]
		hf2 := blake2.New(&blake2.Config{
			Key:      conf.Psk,
			Personal: []byte(domainStr),
			Size:     32,
			Salt:     []byte{2},
		})
		hf2.Write(h1)
		hf2.Write(signature)
		wh2 := hf2.Sum(nil)
		if subtle.ConstantTimeCompare(wh2, h2) != 1 {
			return
		}
		ciphertextWithNonce := make([]byte, ciphertextWithNonceLen)
		if _, err := io.ReadFull(reader, ciphertextWithNonce); err != nil {
			return
		}

		if ed25519.Verify(conf.SignPk, ciphertextWithNonce, signature) != true {
			return
		}

		hf3 := blake2.New(&blake2.Config{
			Key:      conf.Psk,
			Personal: []byte(domainStr),
			Size:     32,
			Salt:     []byte{3},
		})
		hf3.Write(h2)
		h3 := hf3.Sum(nil)

		storedContentRWMutex.Lock()
		storedContent.signature = signature
		storedContent.ciphertextWithNonce = ciphertextWithNonce
		storedContentRWMutex.Unlock()

		writer.Write(h3)
		if err := writer.Flush(); err != nil {
			return
		}
	} else if operation == byte('G') {
		rbuf := make([]byte, 32)
		if _, err := io.ReadFull(reader, rbuf); err != nil {
			return
		}
		h2 := rbuf
		hf2 := blake2.New(&blake2.Config{
			Key:      conf.Psk,
			Personal: []byte(domainStr),
			Size:     32,
			Salt:     []byte{2},
		})
		hf2.Write(h1)
		wh2 := hf2.Sum(nil)
		if subtle.ConstantTimeCompare(wh2, h2) != 1 {
			return
		}

		storedContentRWMutex.RLock()
		signature := storedContent.signature
		ciphertextWithNonce := storedContent.ciphertextWithNonce
		storedContentRWMutex.RUnlock()

		hf3 := blake2.New(&blake2.Config{
			Key:      conf.Psk,
			Personal: []byte(domainStr),
			Size:     32,
			Salt:     []byte{3},
		})
		hf3.Write(h2)
		hf3.Write(storedContent.signature)
		h3 := hf3.Sum(nil)
		writer.Write(h3)
		ciphertextWithNonceLen := uint64(len(ciphertextWithNonce))
		binary.Write(writer, binary.LittleEndian, ciphertextWithNonceLen)
		writer.Write(signature)
		writer.Write(ciphertextWithNonce)
		if err := writer.Flush(); err != nil {
			log.Fatal(err)
		}
	}
}

func server(conf Conf) {
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

func expandConfigFile(path string) string {
	file, err := homedir.Expand(path)
	if err != nil {
		log.Fatal(err)
	}
	return file
}

func main() {
	isPut := flag.Bool("copy", false, "store content (copy) - default is to retrieve the clipboard content (paste)")
	_ = flag.Bool("paste", false, "retrieve content (paste) - ignored")
	isServer := flag.Bool("server", false, "start a server")
	isGenKeys := flag.Bool("genkeys", false, "generate keys")
	defaultConfigFile := "~/.piknik.toml"
	if runtime.GOOS == "windows" {
		defaultConfigFile = "~/piknik.toml"
	}
	configFile := flag.String("config", defaultConfigFile, "configuration file")
	flag.Parse()
	tomlData, err := ioutil.ReadFile(expandConfigFile(*configFile))
	if err != nil && *isGenKeys == false {
		log.Fatal(err)
	}
	var tomlConf tomlConfig
	if _, err = toml.Decode(string(tomlData), &tomlConf); err != nil {
		log.Fatal(err)
	}
	var conf Conf
	if tomlConf.Listen == "" {
		conf.Listen = "0.0.0.0:8075"
	} else {
		conf.Listen = tomlConf.Listen
	}
	if tomlConf.Connect == "" {
		conf.Connect = "127.0.0.1:8075"
	} else {
		conf.Connect = tomlConf.Connect
	}
	if *isGenKeys {
		genKeys(conf, *configFile)
		return
	}
	pskHex := tomlConf.Psk
	psk, err := hex.DecodeString(pskHex)
	if err != nil {
		log.Fatal(err)
	}
	conf.Psk = psk
	if encryptSkHex := tomlConf.EncryptSk; encryptSkHex != "" {
		encryptSk, err := hex.DecodeString(encryptSkHex)
		if err != nil {
			log.Fatal(err)
		}
		conf.EncryptSk = encryptSk
	}
	if signSkHex := tomlConf.SignSk; signSkHex != "" {
		signSk, err := hex.DecodeString(signSkHex)
		if err != nil {
			log.Fatal(err)
		}
		conf.SignSk = signSk
	}
	if signPkHex := tomlConf.SignPk; signPkHex != "" {
		signPk, err := hex.DecodeString(signPkHex)
		if err != nil {
			log.Fatal(err)
		}
		conf.SignPk = signPk
	}
	if *isServer {
		server(conf)
	} else {
		client(conf, *isPut)
	}
}
