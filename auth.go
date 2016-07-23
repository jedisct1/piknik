package main

import blake2b "github.com/minio/blake2b-simd"

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
	if clientVersion > 3 {
		hf1.Write(r2)
	}
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
	if clientVersion > 2 {
		hf2.Write([]byte{opcode})
	}
	h2 := hf2.Sum(nil)

	return h2
}

func auth2store(conf Conf, clientVersion byte, h1 []byte, opcode byte,
	encryptSkID []byte, signature []byte) []byte {
	hf2, _ := blake2b.New(&blake2b.Config{
		Key:    conf.Psk,
		Person: []byte(DomainStr),
		Size:   32,
		Salt:   []byte{2},
	})
	hf2.Write(h1)
	hf2.Write([]byte{opcode})
	hf2.Write(encryptSkID)
	hf2.Write(signature)
	h2 := hf2.Sum(nil)

	return h2
}

func auth3get(conf Conf, clientVersion byte, h2 []byte, encryptSkID []byte,
	signature []byte) []byte {
	hf3, _ := blake2b.New(&blake2b.Config{
		Key:    conf.Psk,
		Person: []byte(DomainStr),
		Size:   32,
		Salt:   []byte{3},
	})
	hf3.Write(h2)
	hf3.Write(encryptSkID)
	hf3.Write(signature)
	h3 := hf3.Sum(nil)

	return h3
}

func auth3store(conf Conf, clientVersion byte, h2 []byte) []byte {
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
