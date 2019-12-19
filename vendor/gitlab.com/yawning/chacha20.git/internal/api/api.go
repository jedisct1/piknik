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

// Package api provides the ChaCha20 implementation abstract interface.
package api

const (
	// BlockSize is the size of a ChaCha20 block in bytes.
	BlockSize = 64

	// StateSize is the size of the ChaCha20 state as 32 bit unsigned words.
	StateSize = 16

	// HashSize is the size of the HChaCha output in bytes.
	HashSize = 32

	// HNonceSize is the HChaCha20 nonce size in bytes.
	HNonceSize = 16

	// Sigma0 is the first word of the ChaCha constant.
	Sigma0 = uint32(0x61707865)

	// Sigma1 is the second word of the ChaCha constant.
	Sigma1 = uint32(0x3320646e)

	// Sigma2 is the third word of the ChaCha constant.
	Sigma2 = uint32(0x79622d32)

	// Sigma3 is the fourth word of the ChaCha constant.
	Sigma3 = uint32(0x6b206574)
)

// Implementation is a ChaCha20 implementation
type Implementation interface {
	// Name returns the name of the implementation.
	Name() string

	// Blocks calculates the ChaCha20 blocks.  If src is not nil, dst will
	// be set to the XOR of src with the key stream, otherwise dst will be
	// set to the key stream.
	Blocks(x *[StateSize]uint32, dst, src []byte, nrBlocks int)

	// HChaCha calculates the HChaCha20 hash.
	//
	// Note: `dst` is guaranteed to be HashSize bytes.
	HChaCha(key, nonce []byte, dst []byte)
}
