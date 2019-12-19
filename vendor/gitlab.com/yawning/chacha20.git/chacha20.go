// Copryright (C) 2019 Yawning Angel
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package chacha20 implements the ChaCha20 stream cipher.
package chacha20 // import "gitlab.com/yawning/chacha20.git"

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math"

	"gitlab.com/yawning/chacha20.git/internal/api"
	"gitlab.com/yawning/chacha20.git/internal/hardware"
	"gitlab.com/yawning/chacha20.git/internal/ref"
)

const (
	// KeySize is the ChaCha20 key size in bytes.
	KeySize = 32

	// NonceSize is the ChaCha20 nonce size in bytes.
	NonceSize = 8

	// INonceSize is the IETF ChaCha20 nonce size in bytes.
	INonceSize = 12

	// XNonceSize is the XChaCha20 nonce size in bytes.
	XNonceSize = 24

	// HNonceSize is the HChaCha20 nonce size in bytes.
	HNonceSize = 16
)

var (
	// ErrInvalidKey is the error returned when the key is invalid.
	ErrInvalidKey = errors.New("chacha20: key length must be KeySize bytes")

	// ErrInvalidNonce is the error returned when the nonce is invalid.
	ErrInvalidNonce = errors.New("chacha20: nonce length must be NonceSize/INonceSize/XNonceSize bytes")

	// ErrInvalidCounter is the error returned when the counter is invalid.
	ErrInvalidCounter = errors.New("chacha20: block counter is invalid (out of range)")

	supportedImpls []api.Implementation
	activeImpl     api.Implementation

	_ cipher.Stream = (*Cipher)(nil)
)

// Cipher is an instance of ChaCha20/XChaCha20 using a particular key and nonce.
type Cipher struct {
	state [api.StateSize]uint32
	buf   [api.BlockSize]byte

	off  int
	ietf bool
}

// Reset zeros the key data so that it will no longer appear in the process's
// memory.
func (c *Cipher) Reset() {
	for i := range c.state {
		c.state[i] = 0
	}
	for i := range c.buf {
		c.buf[i] = 0
	}
}

// Seek sets the block counter to a given offset.
func (c *Cipher) Seek(blockCounter uint64) error {
	if c.ietf {
		if blockCounter > math.MaxUint32 {
			return ErrInvalidCounter
		}
		c.state[12] = uint32(blockCounter)
	} else {
		c.state[12] = uint32(blockCounter)
		c.state[13] = uint32(blockCounter >> 32)
	}
	c.off = api.BlockSize
	return nil
}

// ReKey reinitializes the ChaCha20/XChaCha20 instance with the provided key
// and nonce.
func (c *Cipher) ReKey(key, nonce []byte) error {
	c.Reset()
	return c.doReKey(key, nonce)
}

func (c *Cipher) doReKey(key, nonce []byte) error {
	if len(key) != KeySize {
		return ErrInvalidKey
	}

	var subKey []byte
	switch len(nonce) {
	case NonceSize, INonceSize:
	case XNonceSize:
		subKey = c.buf[:KeySize]
		activeImpl.HChaCha(key, nonce, subKey)
		key = subKey
		nonce = nonce[16:24]
	default:
		return ErrInvalidNonce
	}

	_ = key[31] // Force bounds check elimination.

	c.state[0] = api.Sigma0
	c.state[1] = api.Sigma1
	c.state[2] = api.Sigma2
	c.state[3] = api.Sigma3
	c.state[4] = binary.LittleEndian.Uint32(key[0:4])
	c.state[5] = binary.LittleEndian.Uint32(key[4:8])
	c.state[6] = binary.LittleEndian.Uint32(key[8:12])
	c.state[7] = binary.LittleEndian.Uint32(key[12:16])
	c.state[8] = binary.LittleEndian.Uint32(key[16:20])
	c.state[9] = binary.LittleEndian.Uint32(key[20:24])
	c.state[10] = binary.LittleEndian.Uint32(key[24:28])
	c.state[11] = binary.LittleEndian.Uint32(key[28:32])
	c.state[12] = 0
	if len(nonce) == INonceSize {
		_ = nonce[11] // Force bounds check elimination.
		c.state[13] = binary.LittleEndian.Uint32(nonce[0:4])
		c.state[14] = binary.LittleEndian.Uint32(nonce[4:8])
		c.state[15] = binary.LittleEndian.Uint32(nonce[8:12])
		c.ietf = true
	} else {
		_ = nonce[7] // Force bounds check elimination.
		c.state[13] = 0
		c.state[14] = binary.LittleEndian.Uint32(nonce[0:4])
		c.state[15] = binary.LittleEndian.Uint32(nonce[4:8])
		c.ietf = false
	}
	c.off = api.BlockSize

	if subKey != nil {
		for i := range subKey {
			subKey[i] = 0
		}
	}

	return nil
}

// New returns a new ChaCha20/XChaCha20 instance.
func New(key, nonce []byte) (*Cipher, error) {
	var c Cipher
	if err := c.doReKey(key, nonce); err != nil {
		return nil, err
	}

	return &c, nil
}

// HChaCha is the HChaCha20 hash function used to make XChaCha.
func HChaCha(key, nonce []byte, dst *[32]byte) {
	activeImpl.HChaCha(key, nonce, dst[:])
}

// XORKeyStream sets dst to the result of XORing src with the key stream.  Dst
// and src may be the same slice but otherwise should not overlap.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		src = src[:len(dst)]
	}

	for remaining := len(src); remaining > 0; {
		// Process multiple blocks at once.
		if c.off == api.BlockSize {
			nrBlocks := remaining / api.BlockSize
			directBytes := nrBlocks * api.BlockSize
			if nrBlocks > 0 {
				c.doBlocks(dst, src, nrBlocks)
				remaining -= directBytes
				if remaining == 0 {
					return
				}
				dst = dst[directBytes:]
				src = src[directBytes:]
			}

			// If there's a partial block, generate 1 block of keystream into
			// the internal buffer.
			c.doBlocks(c.buf[:], nil, 1)
			c.off = 0
		}

		// Process partial blocks from the buffered keystream.
		toXor := api.BlockSize - c.off
		if remaining < toXor {
			toXor = remaining
		}
		if toXor > 0 {
			// The inliner doesn't want to inline this function, but my
			// attempts to force BCE don't seem to work with manual
			// inlining.
			//
			// Taking the extra function call overhead here appears to be
			// worth it.
			c.xorBufBytes(dst, src, toXor)

			dst = dst[toXor:]
			src = src[toXor:]

			remaining -= toXor
		}
	}
}

func (c *Cipher) xorBufBytes(dst, src []byte, n int) {
	// Force bounds check elimination.
	buf := c.buf[c.off:]
	_ = buf[n-1]
	_ = dst[n-1]
	_ = src[n-1]

	for i := 0; i < n; i++ {
		dst[i] = buf[i] ^ src[i]
	}
	c.off += n
}

// KeyStream sets dst to the raw keystream.
func (c *Cipher) KeyStream(dst []byte) {
	for remaining := len(dst); remaining > 0; {
		// Process multiple blocks at once.
		if c.off == api.BlockSize {
			nrBlocks := remaining / api.BlockSize
			directBytes := nrBlocks * api.BlockSize
			if nrBlocks > 0 {
				c.doBlocks(dst, nil, nrBlocks)
				remaining -= directBytes
				if remaining == 0 {
					return
				}
				dst = dst[directBytes:]
			}

			// If there's a partial block, generate 1 block of keystream into
			// the internal buffer.
			c.doBlocks(c.buf[:], nil, 1)
			c.off = 0
		}

		// Process partial blocks from the buffered keystream.
		toCopy := api.BlockSize - c.off
		if remaining < toCopy {
			toCopy = remaining
		}
		if toCopy > 0 {
			copy(dst[:toCopy], c.buf[c.off:c.off+toCopy])
			dst = dst[toCopy:]
			remaining -= toCopy
			c.off += toCopy
		}
	}
}

func (c *Cipher) doBlocks(dst, src []byte, nrBlocks int) {
	if c.ietf {
		ctr := uint64(c.state[12])
		if ctr+uint64(nrBlocks) > math.MaxUint32 {
			panic("chacha20: will exceed key stream per nonce limit")
		}
	}

	activeImpl.Blocks(&c.state, dst, src, nrBlocks)
}

func init() {
	supportedImpls = hardware.Register(supportedImpls)
	supportedImpls = ref.Register(supportedImpls)
	activeImpl = supportedImpls[0]
}
