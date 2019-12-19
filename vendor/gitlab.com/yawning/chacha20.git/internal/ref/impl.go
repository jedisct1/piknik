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

// Package ref provides the portable ChaCha20 implementation.
package ref

import (
	"encoding/binary"
	"math/bits"

	"gitlab.com/yawning/chacha20.git/internal/api"
)

const rounds = 20

// Impl is the reference implementation (exposed for testing).
var Impl = &implRef{}

type implRef struct{}

func (impl *implRef) Name() string {
	return "ref"
}

func (impl *implRef) Blocks(x *[api.StateSize]uint32, dst, src []byte, nrBlocks int) {
	for n := 0; n < nrBlocks; n++ {
		x0, x1, x2, x3 := api.Sigma0, api.Sigma1, api.Sigma2, api.Sigma3
		x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 := x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15]

		for i := rounds; i > 0; i -= 2 {
			// quarterround(x, 0, 4, 8, 12)
			x0 += x4
			x12 ^= x0
			x12 = bits.RotateLeft32(x12, 16)
			x8 += x12
			x4 ^= x8
			x4 = bits.RotateLeft32(x4, 12)
			x0 += x4
			x12 ^= x0
			x12 = bits.RotateLeft32(x12, 8)
			x8 += x12
			x4 ^= x8
			x4 = bits.RotateLeft32(x4, 7)

			// quarterround(x, 1, 5, 9, 13)
			x1 += x5
			x13 ^= x1
			x13 = bits.RotateLeft32(x13, 16)
			x9 += x13
			x5 ^= x9
			x5 = bits.RotateLeft32(x5, 12)
			x1 += x5
			x13 ^= x1
			x13 = bits.RotateLeft32(x13, 8)
			x9 += x13
			x5 ^= x9
			x5 = bits.RotateLeft32(x5, 7)

			// quarterround(x, 2, 6, 10, 14)
			x2 += x6
			x14 ^= x2
			x14 = bits.RotateLeft32(x14, 16)
			x10 += x14
			x6 ^= x10
			x6 = bits.RotateLeft32(x6, 12)
			x2 += x6
			x14 ^= x2
			x14 = bits.RotateLeft32(x14, 8)
			x10 += x14
			x6 ^= x10
			x6 = bits.RotateLeft32(x6, 7)

			// quarterround(x, 3, 7, 11, 15)
			x3 += x7
			x15 ^= x3
			x15 = bits.RotateLeft32(x15, 16)
			x11 += x15
			x7 ^= x11
			x7 = bits.RotateLeft32(x7, 12)
			x3 += x7
			x15 ^= x3
			x15 = bits.RotateLeft32(x15, 8)
			x11 += x15
			x7 ^= x11
			x7 = bits.RotateLeft32(x7, 7)

			// quarterround(x, 0, 5, 10, 15)
			x0 += x5
			x15 ^= x0
			x15 = bits.RotateLeft32(x15, 16)
			x10 += x15
			x5 ^= x10
			x5 = bits.RotateLeft32(x5, 12)
			x0 += x5
			x15 ^= x0
			x15 = bits.RotateLeft32(x15, 8)
			x10 += x15
			x5 ^= x10
			x5 = bits.RotateLeft32(x5, 7)

			// quarterround(x, 1, 6, 11, 12)
			x1 += x6
			x12 ^= x1
			x12 = bits.RotateLeft32(x12, 16)
			x11 += x12
			x6 ^= x11
			x6 = bits.RotateLeft32(x6, 12)
			x1 += x6
			x12 ^= x1
			x12 = bits.RotateLeft32(x12, 8)
			x11 += x12
			x6 ^= x11
			x6 = bits.RotateLeft32(x6, 7)

			// quarterround(x, 2, 7, 8, 13)
			x2 += x7
			x13 ^= x2
			x13 = bits.RotateLeft32(x13, 16)
			x8 += x13
			x7 ^= x8
			x7 = bits.RotateLeft32(x7, 12)
			x2 += x7
			x13 ^= x2
			x13 = bits.RotateLeft32(x13, 8)
			x8 += x13
			x7 ^= x8
			x7 = bits.RotateLeft32(x7, 7)

			// quarterround(x, 3, 4, 9, 14)
			x3 += x4
			x14 ^= x3
			x14 = bits.RotateLeft32(x14, 16)
			x9 += x14
			x4 ^= x9
			x4 = bits.RotateLeft32(x4, 12)
			x3 += x4
			x14 ^= x3
			x14 = bits.RotateLeft32(x14, 8)
			x9 += x14
			x4 ^= x9
			x4 = bits.RotateLeft32(x4, 7)
		}

		x0 += api.Sigma0
		x1 += api.Sigma1
		x2 += api.Sigma2
		x3 += api.Sigma3
		x4 += x[4]
		x5 += x[5]
		x6 += x[6]
		x7 += x[7]
		x8 += x[8]
		x9 += x[9]
		x10 += x[10]
		x11 += x[11]
		x12 += x[12]
		x13 += x[13]
		x14 += x[14]
		x15 += x[15]

		_ = dst[api.BlockSize-1] // Force bounds check elimination.

		if src != nil {
			_ = src[api.BlockSize-1] // Force bounds check elimination.
			binary.LittleEndian.PutUint32(dst[0:4], binary.LittleEndian.Uint32(src[0:4])^x0)
			binary.LittleEndian.PutUint32(dst[4:8], binary.LittleEndian.Uint32(src[4:8])^x1)
			binary.LittleEndian.PutUint32(dst[8:12], binary.LittleEndian.Uint32(src[8:12])^x2)
			binary.LittleEndian.PutUint32(dst[12:16], binary.LittleEndian.Uint32(src[12:16])^x3)
			binary.LittleEndian.PutUint32(dst[16:20], binary.LittleEndian.Uint32(src[16:20])^x4)
			binary.LittleEndian.PutUint32(dst[20:24], binary.LittleEndian.Uint32(src[20:24])^x5)
			binary.LittleEndian.PutUint32(dst[24:28], binary.LittleEndian.Uint32(src[24:28])^x6)
			binary.LittleEndian.PutUint32(dst[28:32], binary.LittleEndian.Uint32(src[28:32])^x7)
			binary.LittleEndian.PutUint32(dst[32:36], binary.LittleEndian.Uint32(src[32:36])^x8)
			binary.LittleEndian.PutUint32(dst[36:40], binary.LittleEndian.Uint32(src[36:40])^x9)
			binary.LittleEndian.PutUint32(dst[40:44], binary.LittleEndian.Uint32(src[40:44])^x10)
			binary.LittleEndian.PutUint32(dst[44:48], binary.LittleEndian.Uint32(src[44:48])^x11)
			binary.LittleEndian.PutUint32(dst[48:52], binary.LittleEndian.Uint32(src[48:52])^x12)
			binary.LittleEndian.PutUint32(dst[52:56], binary.LittleEndian.Uint32(src[52:56])^x13)
			binary.LittleEndian.PutUint32(dst[56:60], binary.LittleEndian.Uint32(src[56:60])^x14)
			binary.LittleEndian.PutUint32(dst[60:64], binary.LittleEndian.Uint32(src[60:64])^x15)
			src = src[api.BlockSize:]
		} else {
			binary.LittleEndian.PutUint32(dst[0:4], x0)
			binary.LittleEndian.PutUint32(dst[4:8], x1)
			binary.LittleEndian.PutUint32(dst[8:12], x2)
			binary.LittleEndian.PutUint32(dst[12:16], x3)
			binary.LittleEndian.PutUint32(dst[16:20], x4)
			binary.LittleEndian.PutUint32(dst[20:24], x5)
			binary.LittleEndian.PutUint32(dst[24:28], x6)
			binary.LittleEndian.PutUint32(dst[28:32], x7)
			binary.LittleEndian.PutUint32(dst[32:36], x8)
			binary.LittleEndian.PutUint32(dst[36:40], x9)
			binary.LittleEndian.PutUint32(dst[40:44], x10)
			binary.LittleEndian.PutUint32(dst[44:48], x11)
			binary.LittleEndian.PutUint32(dst[48:52], x12)
			binary.LittleEndian.PutUint32(dst[52:56], x13)
			binary.LittleEndian.PutUint32(dst[56:60], x14)
			binary.LittleEndian.PutUint32(dst[60:64], x15)
		}
		dst = dst[api.BlockSize:]

		// Stoping at 2^70 bytes per nonce is the user's responsibility.
		ctr := uint64(x[13])<<32 | uint64(x[12])
		ctr++
		x[12] = uint32(ctr)
		x[13] = uint32(ctr >> 32)
	}
}

func (impl *implRef) HChaCha(key, nonce []byte, dst []byte) {
	// Force bounds check elimination.
	_ = key[31]
	_ = nonce[api.HNonceSize-1]

	x0, x1, x2, x3 := api.Sigma0, api.Sigma1, api.Sigma2, api.Sigma3
	x4 := binary.LittleEndian.Uint32(key[0:4])
	x5 := binary.LittleEndian.Uint32(key[4:8])
	x6 := binary.LittleEndian.Uint32(key[8:12])
	x7 := binary.LittleEndian.Uint32(key[12:16])
	x8 := binary.LittleEndian.Uint32(key[16:20])
	x9 := binary.LittleEndian.Uint32(key[20:24])
	x10 := binary.LittleEndian.Uint32(key[24:28])
	x11 := binary.LittleEndian.Uint32(key[28:32])
	x12 := binary.LittleEndian.Uint32(nonce[0:4])
	x13 := binary.LittleEndian.Uint32(nonce[4:8])
	x14 := binary.LittleEndian.Uint32(nonce[8:12])
	x15 := binary.LittleEndian.Uint32(nonce[12:16])

	// Yes, this could be carved out into a function for code reuse (TM)
	// however the go inliner won't inline it.
	for i := rounds; i > 0; i -= 2 {
		// quarterround(x, 0, 4, 8, 12)
		x0 += x4
		x12 ^= x0
		x12 = bits.RotateLeft32(x12, 16)
		x8 += x12
		x4 ^= x8
		x4 = bits.RotateLeft32(x4, 12)
		x0 += x4
		x12 ^= x0
		x12 = bits.RotateLeft32(x12, 8)
		x8 += x12
		x4 ^= x8
		x4 = bits.RotateLeft32(x4, 7)

		// quarterround(x, 1, 5, 9, 13)
		x1 += x5
		x13 ^= x1
		x13 = bits.RotateLeft32(x13, 16)
		x9 += x13
		x5 ^= x9
		x5 = bits.RotateLeft32(x5, 12)
		x1 += x5
		x13 ^= x1
		x13 = bits.RotateLeft32(x13, 8)
		x9 += x13
		x5 ^= x9
		x5 = bits.RotateLeft32(x5, 7)

		// quarterround(x, 2, 6, 10, 14)
		x2 += x6
		x14 ^= x2
		x14 = bits.RotateLeft32(x14, 16)
		x10 += x14
		x6 ^= x10
		x6 = bits.RotateLeft32(x6, 12)
		x2 += x6
		x14 ^= x2
		x14 = bits.RotateLeft32(x14, 8)
		x10 += x14
		x6 ^= x10
		x6 = bits.RotateLeft32(x6, 7)

		// quarterround(x, 3, 7, 11, 15)
		x3 += x7
		x15 ^= x3
		x15 = bits.RotateLeft32(x15, 16)
		x11 += x15
		x7 ^= x11
		x7 = bits.RotateLeft32(x7, 12)
		x3 += x7
		x15 ^= x3
		x15 = bits.RotateLeft32(x15, 8)
		x11 += x15
		x7 ^= x11
		x7 = bits.RotateLeft32(x7, 7)

		// quarterround(x, 0, 5, 10, 15)
		x0 += x5
		x15 ^= x0
		x15 = bits.RotateLeft32(x15, 16)
		x10 += x15
		x5 ^= x10
		x5 = bits.RotateLeft32(x5, 12)
		x0 += x5
		x15 ^= x0
		x15 = bits.RotateLeft32(x15, 8)
		x10 += x15
		x5 ^= x10
		x5 = bits.RotateLeft32(x5, 7)

		// quarterround(x, 1, 6, 11, 12)
		x1 += x6
		x12 ^= x1
		x12 = bits.RotateLeft32(x12, 16)
		x11 += x12
		x6 ^= x11
		x6 = bits.RotateLeft32(x6, 12)
		x1 += x6
		x12 ^= x1
		x12 = bits.RotateLeft32(x12, 8)
		x11 += x12
		x6 ^= x11
		x6 = bits.RotateLeft32(x6, 7)

		// quarterround(x, 2, 7, 8, 13)
		x2 += x7
		x13 ^= x2
		x13 = bits.RotateLeft32(x13, 16)
		x8 += x13
		x7 ^= x8
		x7 = bits.RotateLeft32(x7, 12)
		x2 += x7
		x13 ^= x2
		x13 = bits.RotateLeft32(x13, 8)
		x8 += x13
		x7 ^= x8
		x7 = bits.RotateLeft32(x7, 7)

		// quarterround(x, 3, 4, 9, 14)
		x3 += x4
		x14 ^= x3
		x14 = bits.RotateLeft32(x14, 16)
		x9 += x14
		x4 ^= x9
		x4 = bits.RotateLeft32(x4, 12)
		x3 += x4
		x14 ^= x3
		x14 = bits.RotateLeft32(x14, 8)
		x9 += x14
		x4 ^= x9
		x4 = bits.RotateLeft32(x4, 7)
	}

	// HChaCha returns x0...x3 | x12...x15, which corresponds to the
	// indexes of the ChaCha constant and the indexes of the IV.
	_ = dst[api.HashSize-1] // Force bounds check elimination.
	binary.LittleEndian.PutUint32(dst[0:4], x0)
	binary.LittleEndian.PutUint32(dst[4:8], x1)
	binary.LittleEndian.PutUint32(dst[8:12], x2)
	binary.LittleEndian.PutUint32(dst[12:16], x3)
	binary.LittleEndian.PutUint32(dst[16:20], x12)
	binary.LittleEndian.PutUint32(dst[20:24], x13)
	binary.LittleEndian.PutUint32(dst[24:28], x14)
	binary.LittleEndian.PutUint32(dst[28:32], x15)
}

// Register appends the implementation to the provided slice, and returns the
// new slice.
func Register(impls []api.Implementation) []api.Implementation {
	return append(impls, Impl)
}
