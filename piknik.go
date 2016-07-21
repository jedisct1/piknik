package main

import (
	"encoding/hex"
	"flag"
	"io/ioutil"
	"log"
	"runtime"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/mitchellh/go-homedir"
)

const domainStr = "PK"

type tomlConfig struct {
	Connect   string
	Listen    string
	MaxLen    uint64
	EncryptSk string
	Psk       string
	SignPk    string
	SignSk    string
}

// Conf - Shared config
type Conf struct {
	Connect   string
	Listen    string
	MaxLen    uint64
	EncryptSk []byte
	Psk       []byte
	SignPk    []byte
	SignSk    []byte
}

// StoredContent - Paste buffer
type StoredContent struct {
	signature           []byte
	ciphertextWithNonce []byte
}

var storedContent StoredContent
var storedContentRWMutex sync.RWMutex

func expandConfigFile(path string) string {
	file, err := homedir.Expand(path)
	if err != nil {
		log.Fatal(err)
	}
	return file
}

func main() {
	isCopy := flag.Bool("copy", false, "store content (copy) - default is to retrieve the clipboard content (paste)")
	_ = flag.Bool("paste", false, "retrieve content (paste) - ignored")
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
		ServerMain(conf)
	} else {
		ClientMain(conf, *isCopy)
	}
}
