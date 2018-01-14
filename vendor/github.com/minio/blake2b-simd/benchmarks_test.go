/*
 * Minio Cloud Storage, (C) 2016 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package blake2b

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"
)

func benchmarkHash(b *testing.B, hash func() hash.Hash) {
	b.SetBytes(1024 * 1024)
	var data [1024]byte
	for i := 0; i < b.N; i++ {
		h := hash()
		for j := 0; j < 1024; j++ {
			h.Write(data[:])
		}
		h.Sum(nil)
	}
}

func BenchmarkComparisonMD5(b *testing.B) {
	benchmarkHash(b, md5.New)
}

func BenchmarkComparisonSHA1(b *testing.B) {
	benchmarkHash(b, sha1.New)
}

func BenchmarkComparisonSHA256(b *testing.B) {
	benchmarkHash(b, sha256.New)
}

func BenchmarkComparisonSHA512(b *testing.B) {
	benchmarkHash(b, sha512.New)
}

func BenchmarkComparisonBlake2B(b *testing.B) {
	benchmarkHash(b, New512)
}

// Benchmark blake2b implementation.
var bench = New512()
var buf [128 * 1024]byte

func benchmarkSize(b *testing.B, size int) {
	b.SetBytes(int64(size))
	for i := 0; i < b.N; i++ {
		bench.Reset()
		bench.Write(buf[:size])
		bench.Sum(nil)
	}
}

// Benchmark writes of 64 bytes.
func BenchmarkSize64(b *testing.B) {
	benchmarkSize(b, 64)
}

// Benchmark writes of 128 bytes.
func BenchmarkSize128(b *testing.B) {
	benchmarkSize(b, 128)
}

// Benchmark writes of 1KiB bytes.
func BenchmarkSize1K(b *testing.B) {
	benchmarkSize(b, 1024)
}

// Benchmark writes of 8KiB bytes.
func BenchmarkSize8K(b *testing.B) {
	benchmarkSize(b, 8*1024)
}

// Benchmark writes of 32KiB bytes.
func BenchmarkSize32K(b *testing.B) {
	benchmarkSize(b, 32*1024)
}

// Benchmark writes of 128KiB bytes.
func BenchmarkSize128K(b *testing.B) {
	benchmarkSize(b, 128*1024)
}
