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

// +build amd64,!noasm

package hardware

import (
	"golang.org/x/sys/cpu"

	"gitlab.com/yawning/chacha20.git/internal/api"
)

//go:noescape
func blocksAVX2(s *[api.StateSize]uint32, in, out []byte)

//go:noescape
func hChaChaAVX2(key, nonce []byte, dst *byte)

//go:noescape
func blocksSSSE3(s *[api.StateSize]uint32, in, out []byte)

//go:noescape
func hChaChaSSSE3(key, nonce []byte, dst *byte)

type implAmd64 struct {
	name string

	blocksFn  func(*[api.StateSize]uint32, []byte, []byte, int)
	hChaChaFn func([]byte, []byte, *byte)
}

func (impl *implAmd64) Name() string {
	return impl.name
}

func (impl *implAmd64) Blocks(x *[api.StateSize]uint32, dst, src []byte, nrBlocks int) {
	impl.blocksFn(x, dst, src, nrBlocks)
}

func (impl *implAmd64) HChaCha(key, nonce []byte, dst []byte) {
	impl.hChaChaFn(key, nonce, &dst[0])
}

func blockWrapper(fn func(*[api.StateSize]uint32, []byte, []byte)) func(*[api.StateSize]uint32, []byte, []byte, int) {
	return func(x *[api.StateSize]uint32, dst, src []byte, nrBlocks int) {
		sz := nrBlocks * api.BlockSize
		if src != nil {
			fn(x, src[:sz], dst[:sz])
		} else {
			// Sub-optimal, but the compiler special cases this to an assembly
			// optimized runtime.memclrNoHeapPointers, so it's not terrible.
			for i := range dst[:sz] {
				dst[i] = 0
			}
			fn(x, dst[:sz], dst[:sz])
		}
	}
}

func init() {
	if cpu.X86.HasAVX2 {
		hardwareImpls = append(hardwareImpls, &implAmd64{
			name:      "amd64_avx2",
			blocksFn:  blockWrapper(blocksAVX2),
			hChaChaFn: hChaChaAVX2,
		})
	}
	if cpu.X86.HasSSE3 {
		hardwareImpls = append(hardwareImpls, &implAmd64{
			name:      "amd64_ssse3",
			blocksFn:  blockWrapper(blocksSSSE3),
			hChaChaFn: hChaChaSSSE3,
		})
	}
}
