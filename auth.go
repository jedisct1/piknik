package main

import (
	"encoding/binary"
	"hash"

	blake2b "github.com/minio/blake2b-simd"
)

func auth0(conf Conf, clientVersion byte, r []byte) []byte {
	hf0, _ := blake2b.New(&blake2b.Config{
		Key:    conf.Psk,
		Person: []byte(DomainStr),
		Size:   32,
		Salt:   []byte{0},
	})
	hf0.Write([]byte{clientVersion})
	hf0.Write(r)
	h0 := hf0.Sum(nil)

	return h0
}

func auth1(conf Conf, clientVersion byte, h0 []byte, r2 []byte) []byte {
	hf1, _ := blake2b.New(&blake2b.Config{
		Key:    conf.Psk,
		Person: []byte(DomainStr),
		Size:   32,
		Salt:   []byte{1},
	})
	hf1.Write([]byte{clientVersion})
	hf1.Write(r2)
	hf1.Write(h0)
	h1 := hf1.Sum(nil)

	return h1
}

func auth2get(conf Conf, clientVersion byte, h1 []byte, opcode byte) []byte {
	hf2, _ := blake2b.New(&blake2b.Config{
		Key:    conf.Psk,
		Person: []byte(DomainStr),
		Size:   32,
		Salt:   []byte{2},
	})
	hf2.Write(h1)
	hf2.Write([]byte{opcode})
	h2 := hf2.Sum(nil)

	return h2
}

func auth2store(conf Conf, clientVersion byte, h1 []byte, opcode byte,
	ts []byte, signature []byte,
) []byte {
	hf2, _ := blake2b.New(&blake2b.Config{
		Key:    conf.Psk,
		Person: []byte(DomainStr),
		Size:   32,
		Salt:   []byte{2},
	})
	hf2.Write(h1)
	hf2.Write([]byte{opcode})
	hf2.Write(ts)
	hf2.Write(signature)
	h2 := hf2.Sum(nil)

	return h2
}

func auth3get(conf Conf, clientVersion byte, h2 []byte,
	ts []byte, signature []byte,
) []byte {
	hf3, _ := blake2b.New(&blake2b.Config{
		Key:    conf.Psk,
		Person: []byte(DomainStr),
		Size:   32,
		Salt:   []byte{3},
	})
	hf3.Write(h2)
	hf3.Write(ts)
	hf3.Write(signature)
	h3 := hf3.Sum(nil)

	return h3
}

func auth3store(conf Conf, h2 []byte) []byte {
	hf3, _ := blake2b.New(&blake2b.Config{
		Key:    conf.Psk,
		Person: []byte(DomainStr),
		Size:   32,
		Salt:   []byte{3},
	})
	hf3.Write(h2)
	h3 := hf3.Sum(nil)

	return h3
}

func deriveStreamKey(encryptSk []byte, ts []byte, encryptSkID []byte, noncePrefix []byte, cidBytes []byte) []byte {
	hf, _ := blake2b.New(&blake2b.Config{
		Key:    encryptSk,
		Person: []byte("pkv7-stream-key"),
		Size:   32,
	})
	hf.Write(ts)
	hf.Write(encryptSkID)
	hf.Write(noncePrefix)
	cidLen := make([]byte, 2)
	binary.LittleEndian.PutUint16(cidLen, uint16(len(cidBytes)))
	hf.Write(cidLen)
	hf.Write(cidBytes)
	return hf.Sum(nil)
}

func computeCIDBind(encryptSk []byte, cidBytes []byte) []byte {
	if len(cidBytes) == 0 {
		return make([]byte, 32)
	}
	hf, _ := blake2b.New(&blake2b.Config{
		Key:    encryptSk,
		Person: []byte("pk-v7-cid-bind"),
		Size:   32,
	})
	cidLen := make([]byte, 2)
	binary.LittleEndian.PutUint16(cidLen, uint16(len(cidBytes)))
	hf.Write(cidLen)
	hf.Write(cidBytes)
	return hf.Sum(nil)
}

func newTranscriptHash() hash.Hash {
	hf, _ := blake2b.New(&blake2b.Config{
		Person: []byte("pk-v7-transcript"),
		Size:   32,
	})
	return hf
}

func deriveChunkNonce(noncePrefix []byte, chunkIndex uint64) []byte {
	nonce := make([]byte, 24)
	copy(nonce, noncePrefix)
	binary.LittleEndian.PutUint64(nonce[16:], chunkIndex)
	return nonce
}
