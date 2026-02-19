package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/minio/blake2b-simd"
	"github.com/mitchellh/go-homedir"
)

const (
	Version        = "0.11.0"
	DomainStr      = "PK"
	DefaultListen  = "0.0.0.0:8075"
	DefaultConnect = "127.0.0.1:8075"
	DefaultTTL     = 7 * 24 * time.Hour

	MaxChunk              = 65536
	MaxFutureSkew         = time.Hour
	DefaultMaxWaitPullers = 100
	DefaultMaxStreamBytes = uint64(10 * 1024 * 1024 * 1024)
	DefaultMaxStreamDur   = 24 * time.Hour
)

type tomlConfig struct {
	Connect           string
	Listen            string
	EncryptSk         string
	EncryptSkID       uint64
	Psk               string
	SignPk            string
	SignSk            string
	Timeout           uint
	DataTimeout       uint
	TTL               uint
	MaxStreamBytes    uint64
	MaxStreamDuration uint
	MaxWaitingPullers uint
}

type Conf struct {
	Connect           string
	Listen            string
	MaxClients        uint64
	MaxLen            uint64
	EncryptSk         []byte
	EncryptSkID       []byte
	Psk               []byte
	SignPk            []byte
	SignSk            []byte
	Timeout           time.Duration
	DataTimeout       time.Duration
	TTL               time.Duration
	TrustedIPCount    uint64
	MaxStreamBytes    uint64
	MaxStreamDuration time.Duration
	MaxWaitingPullers uint
}

func expandConfigFile(path string) string {
	file, err := homedir.Expand(path)
	if err != nil {
		log.Fatal(err)
	}
	return file
}

func version() {
	fmt.Printf("\nPiknik v%v (protocol version: %v)\n",
		Version, DefaultClientVersion)
}

func confCheck(conf Conf, isServer bool) {
	if len(conf.Psk) != 32 {
		log.Fatal("Configuration error: the Psk property is either missing or invalid")
	}
	if len(conf.SignPk) != 32 {
		log.Fatal("Configuration error: the SignPk property is either missing or invalid")
	}
	if isServer {
		if len(conf.Listen) < 3 {
			log.Fatal("Configuration error: the Listen property must be valid for a server")
		}
		if conf.MaxClients <= 0 {
			log.Fatal("Configuration error: MaxClients should be at least 1")
		}
	} else {
		if len(conf.Connect) < 3 {
			log.Fatal("Configuration error: the Connect property must be valid for a client")
		}
		if len(conf.EncryptSk) != 32 || len(conf.SignSk) != 64 {
			log.Fatal("Configuration error: the EncryptSk and SignSk properties must be present\n" +
				"and valid in order to use this command in client mode")
		}
		if conf.TTL <= 0 {
			log.Fatal("TTL cannot be 0")
		}
	}
}

func main() {
	log.SetFlags(0)

	isCopy := flag.Bool("copy", false, "store content (copy)")
	_ = flag.Bool("paste", false, "retrieve the content (paste) - this is the default action")
	isMove := flag.Bool("move", false, "retrieve and delete the clipboard content")
	isPush := flag.Bool("push", false, "stream stdin to connected pullers")
	isPull := flag.Bool("pull", false, "wait and receive one stream to stdout")
	cidFlag := flag.String("cid", "", "content identifier label for stream binding")
	isServer := flag.Bool("server", false, "start a server")
	isGenKeys := flag.Bool("genkeys", false, "generate keys")
	isDeterministic := flag.Bool("password", false, "derive the keys from a password (default=random keys)")
	maxClients := flag.Uint64("maxclients", 10, "maximum number of simultaneous client connections")
	maxLenMb := flag.Uint64("maxlen", 0, "maximum content length to accept in Mb (0=unlimited)")
	timeout := flag.Uint("timeout", 10, "connection timeout (seconds)")
	dataTimeout := flag.Uint("datatimeout", 3600, "data transmission timeout (seconds)")
	isVersion := flag.Bool("version", false, "display package version")

	defaultConfigFile := "~/.piknik.toml"
	if runtime.GOOS == "windows" {
		defaultConfigFile = "~/piknik.toml"
	}
	configFile := flag.String("config", defaultConfigFile, "configuration file")
	flag.Parse()
	if *isVersion {
		version()
		return
	}
	tomlData, err := os.ReadFile(expandConfigFile(*configFile))
	if err != nil && !*isGenKeys {
		log.Fatal(err)
	}
	var tomlConf tomlConfig
	if _, err = toml.Decode(string(tomlData), &tomlConf); err != nil {
		log.Fatal(err)
	}
	var conf Conf
	if tomlConf.Listen == "" {
		conf.Listen = DefaultListen
	} else {
		conf.Listen = tomlConf.Listen
	}
	if tomlConf.Connect == "" {
		conf.Connect = DefaultConnect
	} else {
		conf.Connect = tomlConf.Connect
	}
	if *isGenKeys {
		leKey := ""
		if *isDeterministic {
			leKey = getPassword("Password> ")
		}
		genKeys(conf, *configFile, leKey)
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
	if signPkHex := tomlConf.SignPk; signPkHex != "" {
		signPk, err := hex.DecodeString(signPkHex)
		if err != nil {
			log.Fatal(err)
		}
		conf.SignPk = signPk
	}
	if encryptSkID := tomlConf.EncryptSkID; encryptSkID > 0 {
		conf.EncryptSkID = make([]byte, 8)
		binary.LittleEndian.PutUint64(conf.EncryptSkID, encryptSkID)
	} else if len(conf.EncryptSk) > 0 {
		hf, _ := blake2b.New(&blake2b.Config{
			Person: []byte(DomainStr),
			Size:   8,
		})
		hf.Write(conf.EncryptSk)
		encryptSkID := hf.Sum(nil)
		encryptSkID[7] &= 0x7f
		conf.EncryptSkID = encryptSkID
	}
	conf.TTL = DefaultTTL
	if ttl := tomlConf.TTL; ttl > 0 {
		conf.TTL = time.Duration(ttl) * time.Second
	}
	if signSkHex := tomlConf.SignSk; signSkHex != "" {
		signSk, err := hex.DecodeString(signSkHex)
		if err != nil {
			log.Fatal(err)
		}
		switch len(signSk) {
		case 32:
			if len(conf.SignPk) != 32 {
				log.Fatal("Public signing key required")
			}
			signSk = append(signSk, conf.SignPk...)
		case 64:
		default:
			log.Fatal("Unsupported length for the secret signing key")
		}
		conf.SignSk = signSk
	}
	conf.MaxClients = *maxClients
	conf.MaxLen = *maxLenMb * 1024 * 1024
	conf.Timeout = time.Duration(*timeout) * time.Second
	conf.DataTimeout = time.Duration(*dataTimeout) * time.Second
	conf.TrustedIPCount = uint64(float64(conf.MaxClients) * 0.1)
	if conf.TrustedIPCount < 1 {
		conf.TrustedIPCount = 1
	}
	conf.MaxStreamBytes = DefaultMaxStreamBytes
	if tomlConf.MaxStreamBytes > 0 {
		conf.MaxStreamBytes = tomlConf.MaxStreamBytes
	}
	conf.MaxStreamDuration = DefaultMaxStreamDur
	if tomlConf.MaxStreamDuration > 0 {
		conf.MaxStreamDuration = time.Duration(tomlConf.MaxStreamDuration) * time.Second
	}
	conf.MaxWaitingPullers = DefaultMaxWaitPullers
	if tomlConf.MaxWaitingPullers > 0 {
		conf.MaxWaitingPullers = tomlConf.MaxWaitingPullers
	}

	modeCount := 0
	if *isCopy {
		modeCount++
	}
	if *isMove {
		modeCount++
	}
	if *isPush {
		modeCount++
	}
	if *isPull {
		modeCount++
	}
	if modeCount > 1 {
		log.Fatal("Only one of -copy, -move, -push, -pull can be specified")
	}

	cid := *cidFlag
	if cid == "" {
		cid = os.Getenv("PIKNIK_CONTENT_ID")
	}
	if len(cid) > 128 {
		log.Fatal("Content ID (-cid) must be at most 128 bytes")
	}

	confCheck(conf, *isServer)
	if *isServer {
		RunServer(conf)
	} else {
		RunClient(conf, *isCopy, *isMove, *isPush, *isPull, cid)
	}
}
