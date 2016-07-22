package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"io/ioutil"
	"log"
	"runtime"

	"github.com/BurntSushi/toml"
	blake2b "github.com/minio/blake2b-simd"
	"github.com/mitchellh/go-homedir"
)

// DomainStr - BLAKE2 domain (personalization)
const DomainStr = "PK"

type tomlConfig struct {
	Connect     string
	Listen      string
	MaxLen      uint64
	EncryptSk   string
	EncryptSkID uint64
	Psk         string
	SignPk      string
	SignSk      string
}

// Conf - Shared config
type Conf struct {
	Connect     string
	Listen      string
	MaxLen      uint64
	EncryptSk   []byte
	EncryptSkID []byte
	Psk         []byte
	SignPk      []byte
	SignSk      []byte
}

func expandConfigFile(path string) string {
	file, err := homedir.Expand(path)
	if err != nil {
		log.Fatal(err)
	}
	return file
}

func main() {
	isCopy := flag.Bool("copy", false, "store content (copy)")
	_ = flag.Bool("paste", false, "retrieve the content (paste) - this is the default action")
	isMove := flag.Bool("move", false, "retrieve and delete the clipboard content")
	isServer := flag.Bool("server", false, "start a server")
	isGenKeys := flag.Bool("genkeys", false, "generate keys")
	maxLenMb := flag.Uint64("maxlen", 0, "maximum content length to accept in Mb (0=unlimited)")
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
	conf.MaxLen = *maxLenMb * 1024 * 1024
	if *isServer {
		RunServer(conf)
	} else {
		RunClient(conf, *isCopy, *isMove)
	}
}
