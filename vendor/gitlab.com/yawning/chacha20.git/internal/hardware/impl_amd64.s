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

// +build !noasm

#include "textflag.h"

DATA ·chacha_constants<>+0x00(SB)/4, $0x61707865
DATA ·chacha_constants<>+0x04(SB)/4, $0x3320646E
DATA ·chacha_constants<>+0x08(SB)/4, $0x79622D32
DATA ·chacha_constants<>+0x0c(SB)/4, $0x6B206574
DATA ·chacha_constants<>+0x10(SB)/8, $0x0504070601000302
DATA ·chacha_constants<>+0x18(SB)/8, $0x0D0C0F0E09080B0A
DATA ·chacha_constants<>+0x20(SB)/8, $0x0605040702010003
DATA ·chacha_constants<>+0x28(SB)/8, $0x0E0D0C0F0A09080B
GLOBL ·chacha_constants<>(SB), (NOPTR+RODATA), $48

// func blocksAVX2(s *[api.StateSize]uint32, in, out []byte)
TEXT ·blocksAVX2(SB), NOSPLIT, $576-56
	// This is Andrew Moon's AVX2 ChaCha implementation taken from
	// supercop-20171218, with some minor changes, primarily calling
	// convention and assembly dialect related.

	// Align the stack on a 64 byte boundary.
	MOVQ SP, BP
	ADDQ $64, BP
	ANDQ $-64, BP

	// Go calling convention -> SYSV AMD64 (and a fixup).
	MOVQ s+0(FP), DI       // &s -> DI
	ADDQ $16, DI           // Skip the ChaCha constants in the chachaState.
	MOVQ in+8(FP), SI      // &in[0] -> SI
	MOVQ out+32(FP), DX    // &out[0] -> DX
	MOVQ in_len+16(FP), CX // len(in) -> CX

	// Begin the main body of `chacha_blocks_avx2`.
	//
	// Mostly a direct translation except:
	//  * The number of rounds is always 20.
	//  * %rbp is used instead of %rsp.
	LEAQ    ·chacha_constants<>(SB), AX
	VMOVDQU 0(AX), X8
	VMOVDQU 16(AX), X6
	VMOVDQU 32(AX), X7
	VMOVDQU 0(DI), X9
	VMOVDQU 16(DI), X10
	VMOVDQU 32(DI), X11

	// MOVQ 48(DI), AX
	MOVQ    $1, R9
	VMOVDQA X8, 0(BP)
	VMOVDQA X9, 16(BP)
	VMOVDQA X10, 32(BP)
	VMOVDQA X11, 48(BP)

	// MOVQ AX, 64(BP)
	VMOVDQA X6, 448(BP)
	VMOVDQA X6, 464(BP)
	VMOVDQA X7, 480(BP)
	VMOVDQA X7, 496(BP)
	CMPQ    CX, $512
	JAE     chacha_blocks_avx2_atleast512
	CMPQ    CX, $256
	JAE     chacha_blocks_avx2_atleast256
	JMP     chacha_blocks_avx2_below256

chacha_blocks_avx2_atleast512:
	MOVQ 48(BP), AX
	LEAQ 1(AX), R8
	LEAQ 2(AX), R9
	LEAQ 3(AX), R10
	LEAQ 4(AX), BX
	LEAQ 5(AX), R11
	LEAQ 6(AX), R12
	LEAQ 7(AX), R13
	LEAQ 8(AX), R14
	MOVL AX, 128(BP)
	MOVL R8, 4+128(BP)
	MOVL R9, 8+128(BP)
	MOVL R10, 12+128(BP)
	MOVL BX, 16+128(BP)
	MOVL R11, 20+128(BP)
	MOVL R12, 24+128(BP)
	MOVL R13, 28+128(BP)
	SHRQ $32, AX
	SHRQ $32, R8
	SHRQ $32, R9
	SHRQ $32, R10
	SHRQ $32, BX
	SHRQ $32, R11
	SHRQ $32, R12
	SHRQ $32, R13
	MOVL AX, 160(BP)
	MOVL R8, 4+160(BP)
	MOVL R9, 8+160(BP)
	MOVL R10, 12+160(BP)
	MOVL BX, 16+160(BP)
	MOVL R11, 20+160(BP)
	MOVL R12, 24+160(BP)
	MOVL R13, 28+160(BP)
	MOVQ R14, 48(BP)

	// MOVQ 64(BP), AX
	MOVQ         $20, AX
	VPBROADCASTD 0(BP), Y0
	VPBROADCASTD 4+0(BP), Y1
	VPBROADCASTD 8+0(BP), Y2
	VPBROADCASTD 12+0(BP), Y3
	VPBROADCASTD 16(BP), Y4
	VPBROADCASTD 4+16(BP), Y5
	VPBROADCASTD 8+16(BP), Y6
	VPBROADCASTD 12+16(BP), Y7
	VPBROADCASTD 32(BP), Y8
	VPBROADCASTD 4+32(BP), Y9
	VPBROADCASTD 8+32(BP), Y10
	VPBROADCASTD 12+32(BP), Y11
	VPBROADCASTD 8+48(BP), Y14
	VPBROADCASTD 12+48(BP), Y15
	VMOVDQA      128(BP), Y12
	VMOVDQA      160(BP), Y13

chacha_blocks_avx2_mainloop1:
	VPADDD       Y0, Y4, Y0
	VPADDD       Y1, Y5, Y1
	VPXOR        Y12, Y0, Y12
	VPXOR        Y13, Y1, Y13
	VPADDD       Y2, Y6, Y2
	VPADDD       Y3, Y7, Y3
	VPXOR        Y14, Y2, Y14
	VPXOR        Y15, Y3, Y15
	VPSHUFB      448(BP), Y12, Y12
	VPSHUFB      448(BP), Y13, Y13
	VPADDD       Y8, Y12, Y8
	VPADDD       Y9, Y13, Y9
	VPSHUFB      448(BP), Y14, Y14
	VPSHUFB      448(BP), Y15, Y15
	VPADDD       Y10, Y14, Y10
	VPADDD       Y11, Y15, Y11
	VMOVDQA      Y12, 96(BP)
	VPXOR        Y4, Y8, Y4
	VPXOR        Y5, Y9, Y5
	VPSLLD       $ 12, Y4, Y12
	VPSRLD       $20, Y4, Y4
	VPXOR        Y4, Y12, Y4
	VPSLLD       $ 12, Y5, Y12
	VPSRLD       $20, Y5, Y5
	VPXOR        Y5, Y12, Y5
	VPXOR        Y6, Y10, Y6
	VPXOR        Y7, Y11, Y7
	VPSLLD       $ 12, Y6, Y12
	VPSRLD       $20, Y6, Y6
	VPXOR        Y6, Y12, Y6
	VPSLLD       $ 12, Y7, Y12
	VPSRLD       $20, Y7, Y7
	VPXOR        Y7, Y12, Y7
	VPADDD       Y0, Y4, Y0
	VPADDD       Y1, Y5, Y1
	VPXOR        96(BP), Y0, Y12
	VPXOR        Y13, Y1, Y13
	VPADDD       Y2, Y6, Y2
	VPADDD       Y3, Y7, Y3
	VPXOR        Y14, Y2, Y14
	VPXOR        Y15, Y3, Y15
	VPSHUFB      480(BP), Y12, Y12
	VPSHUFB      480(BP), Y13, Y13
	VPADDD       Y8, Y12, Y8
	VPADDD       Y9, Y13, Y9
	VPSHUFB      480(BP), Y14, Y14
	VPSHUFB      480(BP), Y15, Y15
	VPADDD       Y10, Y14, Y10
	VPADDD       Y11, Y15, Y11
	VMOVDQA      Y12, 96(BP)
	VPXOR        Y4, Y8, Y4
	VPXOR        Y5, Y9, Y5
	VPSLLD       $ 7, Y4, Y12
	VPSRLD       $25, Y4, Y4
	VPXOR        Y4, Y12, Y4
	VPSLLD       $ 7, Y5, Y12
	VPSRLD       $25, Y5, Y5
	VPXOR        Y5, Y12, Y5
	VPXOR        Y6, Y10, Y6
	VPXOR        Y7, Y11, Y7
	VPSLLD       $ 7, Y6, Y12
	VPSRLD       $25, Y6, Y6
	VPXOR        Y6, Y12, Y6
	VPSLLD       $ 7, Y7, Y12
	VPSRLD       $25, Y7, Y7
	VPXOR        Y7, Y12, Y7
	VPADDD       Y0, Y5, Y0
	VPADDD       Y1, Y6, Y1
	VPXOR        Y15, Y0, Y15
	VPXOR        96(BP), Y1, Y12
	VPADDD       Y2, Y7, Y2
	VPADDD       Y3, Y4, Y3
	VPXOR        Y13, Y2, Y13
	VPXOR        Y14, Y3, Y14
	VPSHUFB      448(BP), Y15, Y15
	VPSHUFB      448(BP), Y12, Y12
	VPADDD       Y10, Y15, Y10
	VPADDD       Y11, Y12, Y11
	VPSHUFB      448(BP), Y13, Y13
	VPSHUFB      448(BP), Y14, Y14
	VPADDD       Y8, Y13, Y8
	VPADDD       Y9, Y14, Y9
	VMOVDQA      Y15, 96(BP)
	VPXOR        Y5, Y10, Y5
	VPXOR        Y6, Y11, Y6
	VPSLLD       $ 12, Y5, Y15
	VPSRLD       $20, Y5, Y5
	VPXOR        Y5, Y15, Y5
	VPSLLD       $ 12, Y6, Y15
	VPSRLD       $20, Y6, Y6
	VPXOR        Y6, Y15, Y6
	VPXOR        Y7, Y8, Y7
	VPXOR        Y4, Y9, Y4
	VPSLLD       $ 12, Y7, Y15
	VPSRLD       $20, Y7, Y7
	VPXOR        Y7, Y15, Y7
	VPSLLD       $ 12, Y4, Y15
	VPSRLD       $20, Y4, Y4
	VPXOR        Y4, Y15, Y4
	VPADDD       Y0, Y5, Y0
	VPADDD       Y1, Y6, Y1
	VPXOR        96(BP), Y0, Y15
	VPXOR        Y12, Y1, Y12
	VPADDD       Y2, Y7, Y2
	VPADDD       Y3, Y4, Y3
	VPXOR        Y13, Y2, Y13
	VPXOR        Y14, Y3, Y14
	VPSHUFB      480(BP), Y15, Y15
	VPSHUFB      480(BP), Y12, Y12
	VPADDD       Y10, Y15, Y10
	VPADDD       Y11, Y12, Y11
	VPSHUFB      480(BP), Y13, Y13
	VPSHUFB      480(BP), Y14, Y14
	VPADDD       Y8, Y13, Y8
	VPADDD       Y9, Y14, Y9
	VMOVDQA      Y15, 96(BP)
	VPXOR        Y5, Y10, Y5
	VPXOR        Y6, Y11, Y6
	VPSLLD       $ 7, Y5, Y15
	VPSRLD       $25, Y5, Y5
	VPXOR        Y5, Y15, Y5
	VPSLLD       $ 7, Y6, Y15
	VPSRLD       $25, Y6, Y6
	VPXOR        Y6, Y15, Y6
	VPXOR        Y7, Y8, Y7
	VPXOR        Y4, Y9, Y4
	VPSLLD       $ 7, Y7, Y15
	VPSRLD       $25, Y7, Y7
	VPXOR        Y7, Y15, Y7
	VPSLLD       $ 7, Y4, Y15
	VPSRLD       $25, Y4, Y4
	VPXOR        Y4, Y15, Y4
	VMOVDQA      96(BP), Y15
	SUBQ         $2, AX
	JNZ          chacha_blocks_avx2_mainloop1
	VMOVDQA      Y8, 192(BP)
	VMOVDQA      Y9, 224(BP)
	VMOVDQA      Y10, 256(BP)
	VMOVDQA      Y11, 288(BP)
	VMOVDQA      Y12, 320(BP)
	VMOVDQA      Y13, 352(BP)
	VMOVDQA      Y14, 384(BP)
	VMOVDQA      Y15, 416(BP)
	VPBROADCASTD 0(BP), Y8
	VPBROADCASTD 4+0(BP), Y9
	VPBROADCASTD 8+0(BP), Y10
	VPBROADCASTD 12+0(BP), Y11
	VPBROADCASTD 16(BP), Y12
	VPBROADCASTD 4+16(BP), Y13
	VPBROADCASTD 8+16(BP), Y14
	VPBROADCASTD 12+16(BP), Y15
	VPADDD       Y8, Y0, Y0
	VPADDD       Y9, Y1, Y1
	VPADDD       Y10, Y2, Y2
	VPADDD       Y11, Y3, Y3
	VPADDD       Y12, Y4, Y4
	VPADDD       Y13, Y5, Y5
	VPADDD       Y14, Y6, Y6
	VPADDD       Y15, Y7, Y7
	VPUNPCKLDQ   Y1, Y0, Y8
	VPUNPCKLDQ   Y3, Y2, Y9
	VPUNPCKHDQ   Y1, Y0, Y12
	VPUNPCKHDQ   Y3, Y2, Y13
	VPUNPCKLDQ   Y5, Y4, Y10
	VPUNPCKLDQ   Y7, Y6, Y11
	VPUNPCKHDQ   Y5, Y4, Y14
	VPUNPCKHDQ   Y7, Y6, Y15
	VPUNPCKLQDQ  Y9, Y8, Y0
	VPUNPCKLQDQ  Y11, Y10, Y1
	VPUNPCKHQDQ  Y9, Y8, Y2
	VPUNPCKHQDQ  Y11, Y10, Y3
	VPUNPCKLQDQ  Y13, Y12, Y4
	VPUNPCKLQDQ  Y15, Y14, Y5
	VPUNPCKHQDQ  Y13, Y12, Y6
	VPUNPCKHQDQ  Y15, Y14, Y7
	VPERM2I128   $0x20, Y1, Y0, Y8
	VPERM2I128   $0x20, Y3, Y2, Y9
	VPERM2I128   $0x31, Y1, Y0, Y12
	VPERM2I128   $0x31, Y3, Y2, Y13
	VPERM2I128   $0x20, Y5, Y4, Y10
	VPERM2I128   $0x20, Y7, Y6, Y11
	VPERM2I128   $0x31, Y5, Y4, Y14
	VPERM2I128   $0x31, Y7, Y6, Y15
	ANDQ         SI, SI
	JZ           chacha_blocks_avx2_noinput1
	VPXOR        0(SI), Y8, Y8
	VPXOR        64(SI), Y9, Y9
	VPXOR        128(SI), Y10, Y10
	VPXOR        192(SI), Y11, Y11
	VPXOR        256(SI), Y12, Y12
	VPXOR        320(SI), Y13, Y13
	VPXOR        384(SI), Y14, Y14
	VPXOR        448(SI), Y15, Y15
	VMOVDQU      Y8, 0(DX)
	VMOVDQU      Y9, 64(DX)
	VMOVDQU      Y10, 128(DX)
	VMOVDQU      Y11, 192(DX)
	VMOVDQU      Y12, 256(DX)
	VMOVDQU      Y13, 320(DX)
	VMOVDQU      Y14, 384(DX)
	VMOVDQU      Y15, 448(DX)
	VMOVDQA      192(BP), Y0
	VMOVDQA      224(BP), Y1
	VMOVDQA      256(BP), Y2
	VMOVDQA      288(BP), Y3
	VMOVDQA      320(BP), Y4
	VMOVDQA      352(BP), Y5
	VMOVDQA      384(BP), Y6
	VMOVDQA      416(BP), Y7
	VPBROADCASTD 32(BP), Y8
	VPBROADCASTD 4+32(BP), Y9
	VPBROADCASTD 8+32(BP), Y10
	VPBROADCASTD 12+32(BP), Y11
	VMOVDQA      128(BP), Y12
	VMOVDQA      160(BP), Y13
	VPBROADCASTD 8+48(BP), Y14
	VPBROADCASTD 12+48(BP), Y15
	VPADDD       Y8, Y0, Y0
	VPADDD       Y9, Y1, Y1
	VPADDD       Y10, Y2, Y2
	VPADDD       Y11, Y3, Y3
	VPADDD       Y12, Y4, Y4
	VPADDD       Y13, Y5, Y5
	VPADDD       Y14, Y6, Y6
	VPADDD       Y15, Y7, Y7
	VPUNPCKLDQ   Y1, Y0, Y8
	VPUNPCKLDQ   Y3, Y2, Y9
	VPUNPCKHDQ   Y1, Y0, Y12
	VPUNPCKHDQ   Y3, Y2, Y13
	VPUNPCKLDQ   Y5, Y4, Y10
	VPUNPCKLDQ   Y7, Y6, Y11
	VPUNPCKHDQ   Y5, Y4, Y14
	VPUNPCKHDQ   Y7, Y6, Y15
	VPUNPCKLQDQ  Y9, Y8, Y0
	VPUNPCKLQDQ  Y11, Y10, Y1
	VPUNPCKHQDQ  Y9, Y8, Y2
	VPUNPCKHQDQ  Y11, Y10, Y3
	VPUNPCKLQDQ  Y13, Y12, Y4
	VPUNPCKLQDQ  Y15, Y14, Y5
	VPUNPCKHQDQ  Y13, Y12, Y6
	VPUNPCKHQDQ  Y15, Y14, Y7
	VPERM2I128   $0x20, Y1, Y0, Y8
	VPERM2I128   $0x20, Y3, Y2, Y9
	VPERM2I128   $0x31, Y1, Y0, Y12
	VPERM2I128   $0x31, Y3, Y2, Y13
	VPERM2I128   $0x20, Y5, Y4, Y10
	VPERM2I128   $0x20, Y7, Y6, Y11
	VPERM2I128   $0x31, Y5, Y4, Y14
	VPERM2I128   $0x31, Y7, Y6, Y15
	VPXOR        32(SI), Y8, Y8
	VPXOR        96(SI), Y9, Y9
	VPXOR        160(SI), Y10, Y10
	VPXOR        224(SI), Y11, Y11
	VPXOR        288(SI), Y12, Y12
	VPXOR        352(SI), Y13, Y13
	VPXOR        416(SI), Y14, Y14
	VPXOR        480(SI), Y15, Y15
	VMOVDQU      Y8, 32(DX)
	VMOVDQU      Y9, 96(DX)
	VMOVDQU      Y10, 160(DX)
	VMOVDQU      Y11, 224(DX)
	VMOVDQU      Y12, 288(DX)
	VMOVDQU      Y13, 352(DX)
	VMOVDQU      Y14, 416(DX)
	VMOVDQU      Y15, 480(DX)
	ADDQ         $512, SI
	JMP          chacha_blocks_avx2_mainloop1_cont

chacha_blocks_avx2_noinput1:
	VMOVDQU      Y8, 0(DX)
	VMOVDQU      Y9, 64(DX)
	VMOVDQU      Y10, 128(DX)
	VMOVDQU      Y11, 192(DX)
	VMOVDQU      Y12, 256(DX)
	VMOVDQU      Y13, 320(DX)
	VMOVDQU      Y14, 384(DX)
	VMOVDQU      Y15, 448(DX)
	VMOVDQA      192(BP), Y0
	VMOVDQA      224(BP), Y1
	VMOVDQA      256(BP), Y2
	VMOVDQA      288(BP), Y3
	VMOVDQA      320(BP), Y4
	VMOVDQA      352(BP), Y5
	VMOVDQA      384(BP), Y6
	VMOVDQA      416(BP), Y7
	VPBROADCASTD 32(BP), Y8
	VPBROADCASTD 4+32(BP), Y9
	VPBROADCASTD 8+32(BP), Y10
	VPBROADCASTD 12+32(BP), Y11
	VMOVDQA      128(BP), Y12
	VMOVDQA      160(BP), Y13
	VPBROADCASTD 8+48(BP), Y14
	VPBROADCASTD 12+48(BP), Y15
	VPADDD       Y8, Y0, Y0
	VPADDD       Y9, Y1, Y1
	VPADDD       Y10, Y2, Y2
	VPADDD       Y11, Y3, Y3
	VPADDD       Y12, Y4, Y4
	VPADDD       Y13, Y5, Y5
	VPADDD       Y14, Y6, Y6
	VPADDD       Y15, Y7, Y7
	VPUNPCKLDQ   Y1, Y0, Y8
	VPUNPCKLDQ   Y3, Y2, Y9
	VPUNPCKHDQ   Y1, Y0, Y12
	VPUNPCKHDQ   Y3, Y2, Y13
	VPUNPCKLDQ   Y5, Y4, Y10
	VPUNPCKLDQ   Y7, Y6, Y11
	VPUNPCKHDQ   Y5, Y4, Y14
	VPUNPCKHDQ   Y7, Y6, Y15
	VPUNPCKLQDQ  Y9, Y8, Y0
	VPUNPCKLQDQ  Y11, Y10, Y1
	VPUNPCKHQDQ  Y9, Y8, Y2
	VPUNPCKHQDQ  Y11, Y10, Y3
	VPUNPCKLQDQ  Y13, Y12, Y4
	VPUNPCKLQDQ  Y15, Y14, Y5
	VPUNPCKHQDQ  Y13, Y12, Y6
	VPUNPCKHQDQ  Y15, Y14, Y7
	VPERM2I128   $0x20, Y1, Y0, Y8
	VPERM2I128   $0x20, Y3, Y2, Y9
	VPERM2I128   $0x31, Y1, Y0, Y12
	VPERM2I128   $0x31, Y3, Y2, Y13
	VPERM2I128   $0x20, Y5, Y4, Y10
	VPERM2I128   $0x20, Y7, Y6, Y11
	VPERM2I128   $0x31, Y5, Y4, Y14
	VPERM2I128   $0x31, Y7, Y6, Y15
	VMOVDQU      Y8, 32(DX)
	VMOVDQU      Y9, 96(DX)
	VMOVDQU      Y10, 160(DX)
	VMOVDQU      Y11, 224(DX)
	VMOVDQU      Y12, 288(DX)
	VMOVDQU      Y13, 352(DX)
	VMOVDQU      Y14, 416(DX)
	VMOVDQU      Y15, 480(DX)

chacha_blocks_avx2_mainloop1_cont:
	ADDQ $512, DX
	SUBQ $512, CX
	CMPQ CX, $512
	JAE  chacha_blocks_avx2_atleast512
	CMPQ CX, $256
	JB   chacha_blocks_avx2_below256_fixup

chacha_blocks_avx2_atleast256:
	MOVQ 48(BP), AX
	LEAQ 1(AX), R8
	LEAQ 2(AX), R9
	LEAQ 3(AX), R10
	LEAQ 4(AX), BX
	MOVL AX, 128(BP)
	MOVL R8, 4+128(BP)
	MOVL R9, 8+128(BP)
	MOVL R10, 12+128(BP)
	SHRQ $32, AX
	SHRQ $32, R8
	SHRQ $32, R9
	SHRQ $32, R10
	MOVL AX, 160(BP)
	MOVL R8, 4+160(BP)
	MOVL R9, 8+160(BP)
	MOVL R10, 12+160(BP)
	MOVQ BX, 48(BP)

	// MOVQ 64(BP), AX
	MOVQ         $20, AX
	VPBROADCASTD 0(BP), X0
	VPBROADCASTD 4+0(BP), X1
	VPBROADCASTD 8+0(BP), X2
	VPBROADCASTD 12+0(BP), X3
	VPBROADCASTD 16(BP), X4
	VPBROADCASTD 4+16(BP), X5
	VPBROADCASTD 8+16(BP), X6
	VPBROADCASTD 12+16(BP), X7
	VPBROADCASTD 32(BP), X8
	VPBROADCASTD 4+32(BP), X9
	VPBROADCASTD 8+32(BP), X10
	VPBROADCASTD 12+32(BP), X11
	VMOVDQA      128(BP), X12
	VMOVDQA      160(BP), X13
	VPBROADCASTD 8+48(BP), X14
	VPBROADCASTD 12+48(BP), X15

chacha_blocks_avx2_mainloop2:
	VPADDD       X0, X4, X0
	VPADDD       X1, X5, X1
	VPXOR        X12, X0, X12
	VPXOR        X13, X1, X13
	VPADDD       X2, X6, X2
	VPADDD       X3, X7, X3
	VPXOR        X14, X2, X14
	VPXOR        X15, X3, X15
	VPSHUFB      448(BP), X12, X12
	VPSHUFB      448(BP), X13, X13
	VPADDD       X8, X12, X8
	VPADDD       X9, X13, X9
	VPSHUFB      448(BP), X14, X14
	VPSHUFB      448(BP), X15, X15
	VPADDD       X10, X14, X10
	VPADDD       X11, X15, X11
	VMOVDQA      X12, 96(BP)
	VPXOR        X4, X8, X4
	VPXOR        X5, X9, X5
	VPSLLD       $ 12, X4, X12
	VPSRLD       $20, X4, X4
	VPXOR        X4, X12, X4
	VPSLLD       $ 12, X5, X12
	VPSRLD       $20, X5, X5
	VPXOR        X5, X12, X5
	VPXOR        X6, X10, X6
	VPXOR        X7, X11, X7
	VPSLLD       $ 12, X6, X12
	VPSRLD       $20, X6, X6
	VPXOR        X6, X12, X6
	VPSLLD       $ 12, X7, X12
	VPSRLD       $20, X7, X7
	VPXOR        X7, X12, X7
	VPADDD       X0, X4, X0
	VPADDD       X1, X5, X1
	VPXOR        96(BP), X0, X12
	VPXOR        X13, X1, X13
	VPADDD       X2, X6, X2
	VPADDD       X3, X7, X3
	VPXOR        X14, X2, X14
	VPXOR        X15, X3, X15
	VPSHUFB      480(BP), X12, X12
	VPSHUFB      480(BP), X13, X13
	VPADDD       X8, X12, X8
	VPADDD       X9, X13, X9
	VPSHUFB      480(BP), X14, X14
	VPSHUFB      480(BP), X15, X15
	VPADDD       X10, X14, X10
	VPADDD       X11, X15, X11
	VMOVDQA      X12, 96(BP)
	VPXOR        X4, X8, X4
	VPXOR        X5, X9, X5
	VPSLLD       $ 7, X4, X12
	VPSRLD       $25, X4, X4
	VPXOR        X4, X12, X4
	VPSLLD       $ 7, X5, X12
	VPSRLD       $25, X5, X5
	VPXOR        X5, X12, X5
	VPXOR        X6, X10, X6
	VPXOR        X7, X11, X7
	VPSLLD       $ 7, X6, X12
	VPSRLD       $25, X6, X6
	VPXOR        X6, X12, X6
	VPSLLD       $ 7, X7, X12
	VPSRLD       $25, X7, X7
	VPXOR        X7, X12, X7
	VPADDD       X0, X5, X0
	VPADDD       X1, X6, X1
	VPXOR        X15, X0, X15
	VPXOR        96(BP), X1, X12
	VPADDD       X2, X7, X2
	VPADDD       X3, X4, X3
	VPXOR        X13, X2, X13
	VPXOR        X14, X3, X14
	VPSHUFB      448(BP), X15, X15
	VPSHUFB      448(BP), X12, X12
	VPADDD       X10, X15, X10
	VPADDD       X11, X12, X11
	VPSHUFB      448(BP), X13, X13
	VPSHUFB      448(BP), X14, X14
	VPADDD       X8, X13, X8
	VPADDD       X9, X14, X9
	VMOVDQA      X15, 96(BP)
	VPXOR        X5, X10, X5
	VPXOR        X6, X11, X6
	VPSLLD       $ 12, X5, X15
	VPSRLD       $20, X5, X5
	VPXOR        X5, X15, X5
	VPSLLD       $ 12, X6, X15
	VPSRLD       $20, X6, X6
	VPXOR        X6, X15, X6
	VPXOR        X7, X8, X7
	VPXOR        X4, X9, X4
	VPSLLD       $ 12, X7, X15
	VPSRLD       $20, X7, X7
	VPXOR        X7, X15, X7
	VPSLLD       $ 12, X4, X15
	VPSRLD       $20, X4, X4
	VPXOR        X4, X15, X4
	VPADDD       X0, X5, X0
	VPADDD       X1, X6, X1
	VPXOR        96(BP), X0, X15
	VPXOR        X12, X1, X12
	VPADDD       X2, X7, X2
	VPADDD       X3, X4, X3
	VPXOR        X13, X2, X13
	VPXOR        X14, X3, X14
	VPSHUFB      480(BP), X15, X15
	VPSHUFB      480(BP), X12, X12
	VPADDD       X10, X15, X10
	VPADDD       X11, X12, X11
	VPSHUFB      480(BP), X13, X13
	VPSHUFB      480(BP), X14, X14
	VPADDD       X8, X13, X8
	VPADDD       X9, X14, X9
	VMOVDQA      X15, 96(BP)
	VPXOR        X5, X10, X5
	VPXOR        X6, X11, X6
	VPSLLD       $ 7, X5, X15
	VPSRLD       $25, X5, X5
	VPXOR        X5, X15, X5
	VPSLLD       $ 7, X6, X15
	VPSRLD       $25, X6, X6
	VPXOR        X6, X15, X6
	VPXOR        X7, X8, X7
	VPXOR        X4, X9, X4
	VPSLLD       $ 7, X7, X15
	VPSRLD       $25, X7, X7
	VPXOR        X7, X15, X7
	VPSLLD       $ 7, X4, X15
	VPSRLD       $25, X4, X4
	VPXOR        X4, X15, X4
	VMOVDQA      96(BP), X15
	SUBQ         $2, AX
	JNZ          chacha_blocks_avx2_mainloop2
	VMOVDQA      X8, 192(BP)
	VMOVDQA      X9, 208(BP)
	VMOVDQA      X10, 224(BP)
	VMOVDQA      X11, 240(BP)
	VMOVDQA      X12, 256(BP)
	VMOVDQA      X13, 272(BP)
	VMOVDQA      X14, 288(BP)
	VMOVDQA      X15, 304(BP)
	VPBROADCASTD 0(BP), X8
	VPBROADCASTD 4+0(BP), X9
	VPBROADCASTD 8+0(BP), X10
	VPBROADCASTD 12+0(BP), X11
	VPBROADCASTD 16(BP), X12
	VPBROADCASTD 4+16(BP), X13
	VPBROADCASTD 8+16(BP), X14
	VPBROADCASTD 12+16(BP), X15
	VPADDD       X8, X0, X0
	VPADDD       X9, X1, X1
	VPADDD       X10, X2, X2
	VPADDD       X11, X3, X3
	VPADDD       X12, X4, X4
	VPADDD       X13, X5, X5
	VPADDD       X14, X6, X6
	VPADDD       X15, X7, X7
	VPUNPCKLDQ   X1, X0, X8
	VPUNPCKLDQ   X3, X2, X9
	VPUNPCKHDQ   X1, X0, X12
	VPUNPCKHDQ   X3, X2, X13
	VPUNPCKLDQ   X5, X4, X10
	VPUNPCKLDQ   X7, X6, X11
	VPUNPCKHDQ   X5, X4, X14
	VPUNPCKHDQ   X7, X6, X15
	VPUNPCKLQDQ  X9, X8, X0
	VPUNPCKLQDQ  X11, X10, X1
	VPUNPCKHQDQ  X9, X8, X2
	VPUNPCKHQDQ  X11, X10, X3
	VPUNPCKLQDQ  X13, X12, X4
	VPUNPCKLQDQ  X15, X14, X5
	VPUNPCKHQDQ  X13, X12, X6
	VPUNPCKHQDQ  X15, X14, X7
	ANDQ         SI, SI
	JZ           chacha_blocks_avx2_noinput2
	VPXOR        0(SI), X0, X0
	VPXOR        16(SI), X1, X1
	VPXOR        64(SI), X2, X2
	VPXOR        80(SI), X3, X3
	VPXOR        128(SI), X4, X4
	VPXOR        144(SI), X5, X5
	VPXOR        192(SI), X6, X6
	VPXOR        208(SI), X7, X7
	VMOVDQU      X0, 0(DX)
	VMOVDQU      X1, 16(DX)
	VMOVDQU      X2, 64(DX)
	VMOVDQU      X3, 80(DX)
	VMOVDQU      X4, 128(DX)
	VMOVDQU      X5, 144(DX)
	VMOVDQU      X6, 192(DX)
	VMOVDQU      X7, 208(DX)
	VMOVDQA      192(BP), X0
	VMOVDQA      208(BP), X1
	VMOVDQA      224(BP), X2
	VMOVDQA      240(BP), X3
	VMOVDQA      256(BP), X4
	VMOVDQA      272(BP), X5
	VMOVDQA      288(BP), X6
	VMOVDQA      304(BP), X7
	VPBROADCASTD 32(BP), X8
	VPBROADCASTD 4+32(BP), X9
	VPBROADCASTD 8+32(BP), X10
	VPBROADCASTD 12+32(BP), X11
	VMOVDQA      128(BP), X12
	VMOVDQA      160(BP), X13
	VPBROADCASTD 8+48(BP), X14
	VPBROADCASTD 12+48(BP), X15
	VPADDD       X8, X0, X0
	VPADDD       X9, X1, X1
	VPADDD       X10, X2, X2
	VPADDD       X11, X3, X3
	VPADDD       X12, X4, X4
	VPADDD       X13, X5, X5
	VPADDD       X14, X6, X6
	VPADDD       X15, X7, X7
	VPUNPCKLDQ   X1, X0, X8
	VPUNPCKLDQ   X3, X2, X9
	VPUNPCKHDQ   X1, X0, X12
	VPUNPCKHDQ   X3, X2, X13
	VPUNPCKLDQ   X5, X4, X10
	VPUNPCKLDQ   X7, X6, X11
	VPUNPCKHDQ   X5, X4, X14
	VPUNPCKHDQ   X7, X6, X15
	VPUNPCKLQDQ  X9, X8, X0
	VPUNPCKLQDQ  X11, X10, X1
	VPUNPCKHQDQ  X9, X8, X2
	VPUNPCKHQDQ  X11, X10, X3
	VPUNPCKLQDQ  X13, X12, X4
	VPUNPCKLQDQ  X15, X14, X5
	VPUNPCKHQDQ  X13, X12, X6
	VPUNPCKHQDQ  X15, X14, X7
	VPXOR        32(SI), X0, X0
	VPXOR        48(SI), X1, X1
	VPXOR        96(SI), X2, X2
	VPXOR        112(SI), X3, X3
	VPXOR        160(SI), X4, X4
	VPXOR        176(SI), X5, X5
	VPXOR        224(SI), X6, X6
	VPXOR        240(SI), X7, X7
	VMOVDQU      X0, 32(DX)
	VMOVDQU      X1, 48(DX)
	VMOVDQU      X2, 96(DX)
	VMOVDQU      X3, 112(DX)
	VMOVDQU      X4, 160(DX)
	VMOVDQU      X5, 176(DX)
	VMOVDQU      X6, 224(DX)
	VMOVDQU      X7, 240(DX)
	ADDQ         $256, SI
	JMP          chacha_blocks_avx2_mainloop2_cont

chacha_blocks_avx2_noinput2:
	VMOVDQU      X0, 0(DX)
	VMOVDQU      X1, 16(DX)
	VMOVDQU      X2, 64(DX)
	VMOVDQU      X3, 80(DX)
	VMOVDQU      X4, 128(DX)
	VMOVDQU      X5, 144(DX)
	VMOVDQU      X6, 192(DX)
	VMOVDQU      X7, 208(DX)
	VMOVDQA      192(BP), X0
	VMOVDQA      208(BP), X1
	VMOVDQA      224(BP), X2
	VMOVDQA      240(BP), X3
	VMOVDQA      256(BP), X4
	VMOVDQA      272(BP), X5
	VMOVDQA      288(BP), X6
	VMOVDQA      304(BP), X7
	VPBROADCASTD 32(BP), X8
	VPBROADCASTD 4+32(BP), X9
	VPBROADCASTD 8+32(BP), X10
	VPBROADCASTD 12+32(BP), X11
	VMOVDQA      128(BP), X12
	VMOVDQA      160(BP), X13
	VPBROADCASTD 8+48(BP), X14
	VPBROADCASTD 12+48(BP), X15
	VPADDD       X8, X0, X0
	VPADDD       X9, X1, X1
	VPADDD       X10, X2, X2
	VPADDD       X11, X3, X3
	VPADDD       X12, X4, X4
	VPADDD       X13, X5, X5
	VPADDD       X14, X6, X6
	VPADDD       X15, X7, X7
	VPUNPCKLDQ   X1, X0, X8
	VPUNPCKLDQ   X3, X2, X9
	VPUNPCKHDQ   X1, X0, X12
	VPUNPCKHDQ   X3, X2, X13
	VPUNPCKLDQ   X5, X4, X10
	VPUNPCKLDQ   X7, X6, X11
	VPUNPCKHDQ   X5, X4, X14
	VPUNPCKHDQ   X7, X6, X15
	VPUNPCKLQDQ  X9, X8, X0
	VPUNPCKLQDQ  X11, X10, X1
	VPUNPCKHQDQ  X9, X8, X2
	VPUNPCKHQDQ  X11, X10, X3
	VPUNPCKLQDQ  X13, X12, X4
	VPUNPCKLQDQ  X15, X14, X5
	VPUNPCKHQDQ  X13, X12, X6
	VPUNPCKHQDQ  X15, X14, X7
	VMOVDQU      X0, 32(DX)
	VMOVDQU      X1, 48(DX)
	VMOVDQU      X2, 96(DX)
	VMOVDQU      X3, 112(DX)
	VMOVDQU      X4, 160(DX)
	VMOVDQU      X5, 176(DX)
	VMOVDQU      X6, 224(DX)
	VMOVDQU      X7, 240(DX)

chacha_blocks_avx2_mainloop2_cont:
	ADDQ $256, DX
	SUBQ $256, CX
	CMPQ CX, $256
	JAE  chacha_blocks_avx2_atleast256

chacha_blocks_avx2_below256_fixup:
	VMOVDQA 448(BP), X6
	VMOVDQA 480(BP), X7
	VMOVDQA 0(BP), X8
	VMOVDQA 16(BP), X9
	VMOVDQA 32(BP), X10
	VMOVDQA 48(BP), X11
	MOVQ    $1, R9

chacha_blocks_avx2_below256:
	VMOVQ R9, X5
	ANDQ  CX, CX
	JZ    chacha_blocks_avx2_done
	CMPQ  CX, $64
	JAE   chacha_blocks_avx2_above63
	MOVQ  DX, R9
	ANDQ  SI, SI
	JZ    chacha_blocks_avx2_noinput3
	MOVQ  CX, R10
	MOVQ  BP, DX
	ADDQ  R10, SI
	ADDQ  R10, DX
	NEGQ  R10

chacha_blocks_avx2_copyinput:
	MOVB (SI)(R10*1), AX
	MOVB AX, (DX)(R10*1)
	INCQ R10
	JNZ  chacha_blocks_avx2_copyinput
	MOVQ BP, SI

chacha_blocks_avx2_noinput3:
	MOVQ BP, DX

chacha_blocks_avx2_above63:
	VMOVDQA X8, X0
	VMOVDQA X9, X1
	VMOVDQA X10, X2
	VMOVDQA X11, X3

	// MOVQ 64(BP), AX
	MOVQ $20, AX

chacha_blocks_avx2_mainloop3:
	VPADDD  X0, X1, X0
	VPXOR   X3, X0, X3
	VPSHUFB X6, X3, X3
	VPADDD  X2, X3, X2
	VPXOR   X1, X2, X1
	VPSLLD  $12, X1, X4
	VPSRLD  $20, X1, X1
	VPXOR   X1, X4, X1
	VPADDD  X0, X1, X0
	VPXOR   X3, X0, X3
	VPSHUFB X7, X3, X3
	VPSHUFD $0x93, X0, X0
	VPADDD  X2, X3, X2
	VPSHUFD $0x4e, X3, X3
	VPXOR   X1, X2, X1
	VPSHUFD $0x39, X2, X2
	VPSLLD  $7, X1, X4
	VPSRLD  $25, X1, X1
	VPXOR   X1, X4, X1
	VPADDD  X0, X1, X0
	VPXOR   X3, X0, X3
	VPSHUFB X6, X3, X3
	VPADDD  X2, X3, X2
	VPXOR   X1, X2, X1
	VPSLLD  $12, X1, X4
	VPSRLD  $20, X1, X1
	VPXOR   X1, X4, X1
	VPADDD  X0, X1, X0
	VPXOR   X3, X0, X3
	VPSHUFB X7, X3, X3
	VPSHUFD $0x39, X0, X0
	VPADDD  X2, X3, X2
	VPSHUFD $0x4e, X3, X3
	VPXOR   X1, X2, X1
	VPSHUFD $0x93, X2, X2
	VPSLLD  $7, X1, X4
	VPSRLD  $25, X1, X1
	VPXOR   X1, X4, X1
	SUBQ    $2, AX
	JNZ     chacha_blocks_avx2_mainloop3
	VPADDD  X0, X8, X0
	VPADDD  X1, X9, X1
	VPADDD  X2, X10, X2
	VPADDD  X3, X11, X3
	ANDQ    SI, SI
	JZ      chacha_blocks_avx2_noinput4
	VPXOR   0(SI), X0, X0
	VPXOR   16(SI), X1, X1
	VPXOR   32(SI), X2, X2
	VPXOR   48(SI), X3, X3
	ADDQ    $64, SI

chacha_blocks_avx2_noinput4:
	VMOVDQU X0, 0(DX)
	VMOVDQU X1, 16(DX)
	VMOVDQU X2, 32(DX)
	VMOVDQU X3, 48(DX)
	VPADDQ  X11, X5, X11
	CMPQ    CX, $64
	JBE     chacha_blocks_avx2_mainloop3_finishup
	ADDQ    $64, DX
	SUBQ    $64, CX
	JMP     chacha_blocks_avx2_below256

chacha_blocks_avx2_mainloop3_finishup:
	CMPQ CX, $64
	JE   chacha_blocks_avx2_done
	ADDQ CX, R9
	ADDQ CX, DX
	NEGQ CX

chacha_blocks_avx2_copyoutput:
	MOVB (DX)(CX*1), AX
	MOVB AX, (R9)(CX*1)
	INCQ CX
	JNZ  chacha_blocks_avx2_copyoutput

chacha_blocks_avx2_done:
	VMOVDQU X11, 32(DI)

	VZEROUPPER
	RET

// func hChaChaAVX2(key, nonce []byte, dst *byte)
TEXT ·hChaChaAVX2(SB), NOSPLIT|NOFRAME, $0-56
	MOVQ key+0(FP), DI
	MOVQ nonce+24(FP), SI
	MOVQ dst+48(FP), DX

	MOVL $20, CX

	LEAQ    ·chacha_constants<>(SB), AX
	VMOVDQA 0(AX), X0
	VMOVDQA 16(AX), X6
	VMOVDQA 32(AX), X5

	VMOVDQU 0(DI), X1
	VMOVDQU 16(DI), X2
	VMOVDQU 0(SI), X3

hhacha_mainloop_avx2:
	VPADDD  X0, X1, X0
	VPXOR   X3, X0, X3
	VPSHUFB X6, X3, X3
	VPADDD  X2, X3, X2
	VPXOR   X1, X2, X1
	VPSLLD  $12, X1, X4
	VPSRLD  $20, X1, X1
	VPXOR   X1, X4, X1
	VPADDD  X0, X1, X0
	VPXOR   X3, X0, X3
	VPSHUFB X5, X3, X3
	VPADDD  X2, X3, X2
	VPXOR   X1, X2, X1
	VPSLLD  $7, X1, X4
	VPSRLD  $25, X1, X1
	VPSHUFD $0x93, X0, X0
	VPXOR   X1, X4, X1
	VPSHUFD $0x4e, X3, X3
	VPADDD  X0, X1, X0
	VPXOR   X3, X0, X3
	VPSHUFB X6, X3, X3
	VPSHUFD $0x39, X2, X2
	VPADDD  X2, X3, X2
	VPXOR   X1, X2, X1
	VPSLLD  $12, X1, X4
	VPSRLD  $20, X1, X1
	VPXOR   X1, X4, X1
	VPADDD  X0, X1, X0
	VPXOR   X3, X0, X3
	VPSHUFB X5, X3, X3
	VPADDD  X2, X3, X2
	VPXOR   X1, X2, X1
	VPSHUFD $0x39, X0, X0
	VPSLLD  $7, X1, X4
	VPSHUFD $0x4e, X3, X3
	VPSRLD  $25, X1, X1
	VPSHUFD $0x93, X2, X2
	VPXOR   X1, X4, X1
	SUBL    $2, CX
	JNE     hhacha_mainloop_avx2

	VMOVDQU X0, (DX)
	VMOVDQU X3, 16(DX)

	VZEROUPPER
	RET

// func blocksSSSE3(s *[api.StateSize]uint32, in, out []byte)
TEXT ·blocksSSSE3(SB), NOSPLIT, $576-56
	// This is Andrew Moon's SSSE3 ChaCha implementation taken from
	// supercop-20190110, with some minor changes, primarily calling
	// convention and assembly dialect related.

	// Align the stack on a 64 byte boundary.
	MOVQ SP, BP
	ADDQ $64, BP
	ANDQ $-64, BP

	// Go calling convention -> SYSV AMD64 (and a fixup).
	MOVQ s+0(FP), DI       // &s -> DI
	ADDQ $16, DI           // Skip the ChaCha constants in the chachaState.
	MOVQ in+8(FP), SI      // &in[0] -> SI
	MOVQ out+32(FP), DX    // &out[0] -> DX
	MOVQ in_len+16(FP), CX // len(in) -> CX

	// Begin the main body of `chacha_blocks_ssse3`.
	//
	// Mostly a direct translation except:
	//  * The number of rounds is always 20.
	//  * %rbp is used instead of BP.
	LEAQ  ·chacha_constants<>(SB), AX
	MOVO  0(AX), X8
	MOVO  16(AX), X6
	MOVO  32(AX), X7
	MOVOU 0(DI), X9
	MOVOU 16(DI), X10
	MOVOU 32(DI), X11

	// MOVQ 48(DI), AX
	MOVQ $1, R9
	MOVO X8, 0(BP)
	MOVO X9, 16(BP)
	MOVO X10, 32(BP)
	MOVO X11, 48(BP)

	MOVO X6, 80(BP)
	MOVO X7, 96(BP)
	// MOVQ AX, 64(BP)
	CMPQ   CX, $256
	JB     chacha_blocks_ssse3_below256
	PSHUFD $0x00, X8, X0
	PSHUFD $0x55, X8, X1
	PSHUFD $0xaa, X8, X2
	PSHUFD $0xff, X8, X3
	MOVO   X0, 128(BP)
	MOVO   X1, 144(BP)
	MOVO   X2, 160(BP)
	MOVO   X3, 176(BP)
	PSHUFD $0x00, X9, X0
	PSHUFD $0x55, X9, X1
	PSHUFD $0xaa, X9, X2
	PSHUFD $0xff, X9, X3
	MOVO   X0, 192(BP)
	MOVO   X1, 208(BP)
	MOVO   X2, 224(BP)
	MOVO   X3, 240(BP)
	PSHUFD $0x00, X10, X0
	PSHUFD $0x55, X10, X1
	PSHUFD $0xaa, X10, X2
	PSHUFD $0xff, X10, X3
	MOVO   X0, 256(BP)
	MOVO   X1, 272(BP)
	MOVO   X2, 288(BP)
	MOVO   X3, 304(BP)
	PSHUFD $0xaa, X11, X0
	PSHUFD $0xff, X11, X1
	MOVO   X0, 352(BP)
	MOVO   X1, 368(BP)
	JMP    chacha_blocks_ssse3_atleast256

// .p2align 6,,63
// # align to 4 mod 64
// nop;nop;nop;nop;
chacha_blocks_ssse3_atleast256:
	MOVQ 48(BP), AX
	LEAQ 1(AX), R8
	LEAQ 2(AX), R9
	LEAQ 3(AX), R10
	LEAQ 4(AX), BX
	MOVL AX, 320(BP)
	MOVL R8, 4+320(BP)
	MOVL R9, 8+320(BP)
	MOVL R10, 12+320(BP)
	SHRQ $32, AX
	SHRQ $32, R8
	SHRQ $32, R9
	SHRQ $32, R10
	MOVL AX, 336(BP)
	MOVL R8, 4+336(BP)
	MOVL R9, 8+336(BP)
	MOVL R10, 12+336(BP)
	MOVQ BX, 48(BP)

	// MOVQ 64(BP), AX
	MOVQ $20, AX
	MOVO 128(BP), X0
	MOVO 144(BP), X1
	MOVO 160(BP), X2
	MOVO 176(BP), X3
	MOVO 192(BP), X4
	MOVO 208(BP), X5
	MOVO 224(BP), X6
	MOVO 240(BP), X7
	MOVO 256(BP), X8
	MOVO 272(BP), X9
	MOVO 288(BP), X10
	MOVO 304(BP), X11
	MOVO 320(BP), X12
	MOVO 336(BP), X13
	MOVO 352(BP), X14
	MOVO 368(BP), X15

chacha_blocks_ssse3_mainloop1:
	PADDD      X4, X0
	PADDD      X5, X1
	PXOR       X0, X12
	PXOR       X1, X13
	PADDD      X6, X2
	PADDD      X7, X3
	PXOR       X2, X14
	PXOR       X3, X15
	PSHUFB     80(BP), X12
	PSHUFB     80(BP), X13
	PADDD      X12, X8
	PADDD      X13, X9
	PSHUFB     80(BP), X14
	PSHUFB     80(BP), X15
	PADDD      X14, X10
	PADDD      X15, X11
	MOVO       X12, 112(BP)
	PXOR       X8, X4
	PXOR       X9, X5
	MOVO       X4, X12
	PSLLL      $ 12, X4
	PSRLL      $20, X12
	PXOR       X12, X4
	MOVO       X5, X12
	PSLLL      $ 12, X5
	PSRLL      $20, X12
	PXOR       X12, X5
	PXOR       X10, X6
	PXOR       X11, X7
	MOVO       X6, X12
	PSLLL      $ 12, X6
	PSRLL      $20, X12
	PXOR       X12, X6
	MOVO       X7, X12
	PSLLL      $ 12, X7
	PSRLL      $20, X12
	PXOR       X12, X7
	MOVO       112(BP), X12
	PADDD      X4, X0
	PADDD      X5, X1
	PXOR       X0, X12
	PXOR       X1, X13
	PADDD      X6, X2
	PADDD      X7, X3
	PXOR       X2, X14
	PXOR       X3, X15
	PSHUFB     96(BP), X12
	PSHUFB     96(BP), X13
	PADDD      X12, X8
	PADDD      X13, X9
	PSHUFB     96(BP), X14
	PSHUFB     96(BP), X15
	PADDD      X14, X10
	PADDD      X15, X11
	MOVO       X12, 112(BP)
	PXOR       X8, X4
	PXOR       X9, X5
	MOVO       X4, X12
	PSLLL      $ 7, X4
	PSRLL      $25, X12
	PXOR       X12, X4
	MOVO       X5, X12
	PSLLL      $ 7, X5
	PSRLL      $25, X12
	PXOR       X12, X5
	PXOR       X10, X6
	PXOR       X11, X7
	MOVO       X6, X12
	PSLLL      $ 7, X6
	PSRLL      $25, X12
	PXOR       X12, X6
	MOVO       X7, X12
	PSLLL      $ 7, X7
	PSRLL      $25, X12
	PXOR       X12, X7
	MOVO       112(BP), X12
	PADDD      X5, X0
	PADDD      X6, X1
	PXOR       X0, X15
	PXOR       X1, X12
	PADDD      X7, X2
	PADDD      X4, X3
	PXOR       X2, X13
	PXOR       X3, X14
	PSHUFB     80(BP), X15
	PSHUFB     80(BP), X12
	PADDD      X15, X10
	PADDD      X12, X11
	PSHUFB     80(BP), X13
	PSHUFB     80(BP), X14
	PADDD      X13, X8
	PADDD      X14, X9
	MOVO       X15, 112(BP)
	PXOR       X10, X5
	PXOR       X11, X6
	MOVO       X5, X15
	PSLLL      $ 12, X5
	PSRLL      $20, X15
	PXOR       X15, X5
	MOVO       X6, X15
	PSLLL      $ 12, X6
	PSRLL      $20, X15
	PXOR       X15, X6
	PXOR       X8, X7
	PXOR       X9, X4
	MOVO       X7, X15
	PSLLL      $ 12, X7
	PSRLL      $20, X15
	PXOR       X15, X7
	MOVO       X4, X15
	PSLLL      $ 12, X4
	PSRLL      $20, X15
	PXOR       X15, X4
	MOVO       112(BP), X15
	PADDD      X5, X0
	PADDD      X6, X1
	PXOR       X0, X15
	PXOR       X1, X12
	PADDD      X7, X2
	PADDD      X4, X3
	PXOR       X2, X13
	PXOR       X3, X14
	PSHUFB     96(BP), X15
	PSHUFB     96(BP), X12
	PADDD      X15, X10
	PADDD      X12, X11
	PSHUFB     96(BP), X13
	PSHUFB     96(BP), X14
	PADDD      X13, X8
	PADDD      X14, X9
	MOVO       X15, 112(BP)
	PXOR       X10, X5
	PXOR       X11, X6
	MOVO       X5, X15
	PSLLL      $ 7, X5
	PSRLL      $25, X15
	PXOR       X15, X5
	MOVO       X6, X15
	PSLLL      $ 7, X6
	PSRLL      $25, X15
	PXOR       X15, X6
	PXOR       X8, X7
	PXOR       X9, X4
	MOVO       X7, X15
	PSLLL      $ 7, X7
	PSRLL      $25, X15
	PXOR       X15, X7
	MOVO       X4, X15
	PSLLL      $ 7, X4
	PSRLL      $25, X15
	PXOR       X15, X4
	SUBQ       $2, AX
	MOVO       112(BP), X15
	JNZ        chacha_blocks_ssse3_mainloop1
	PADDD      128(BP), X0
	PADDD      144(BP), X1
	PADDD      160(BP), X2
	PADDD      176(BP), X3
	PADDD      192(BP), X4
	PADDD      208(BP), X5
	PADDD      224(BP), X6
	PADDD      240(BP), X7
	PADDD      256(BP), X8
	PADDD      272(BP), X9
	PADDD      288(BP), X10
	PADDD      304(BP), X11
	PADDD      320(BP), X12
	PADDD      336(BP), X13
	PADDD      352(BP), X14
	PADDD      368(BP), X15
	MOVO       X8, 384(BP)
	MOVO       X9, 400(BP)
	MOVO       X10, 416(BP)
	MOVO       X11, 432(BP)
	MOVO       X12, 448(BP)
	MOVO       X13, 464(BP)
	MOVO       X14, 480(BP)
	MOVO       X15, 496(BP)
	MOVO       X0, X8
	MOVO       X2, X9
	MOVO       X4, X10
	MOVO       X6, X11
	PUNPCKHLQ  X1, X0
	PUNPCKHLQ  X3, X2
	PUNPCKHLQ  X5, X4
	PUNPCKHLQ  X7, X6
	PUNPCKLLQ  X1, X8
	PUNPCKLLQ  X3, X9
	PUNPCKLLQ  X5, X10
	PUNPCKLLQ  X7, X11
	MOVO       X0, X1
	MOVO       X4, X3
	MOVO       X8, X5
	MOVO       X10, X7
	PUNPCKHQDQ X2, X0
	PUNPCKHQDQ X6, X4
	PUNPCKHQDQ X9, X8
	PUNPCKHQDQ X11, X10
	PUNPCKLQDQ X2, X1
	PUNPCKLQDQ X6, X3
	PUNPCKLQDQ X9, X5
	PUNPCKLQDQ X11, X7
	ANDQ       SI, SI
	JZ         chacha_blocks_ssse3_noinput1
	MOVOU      0(SI), X2
	MOVOU      16(SI), X6
	MOVOU      64(SI), X9
	MOVOU      80(SI), X11
	MOVOU      128(SI), X12
	MOVOU      144(SI), X13
	MOVOU      192(SI), X14
	MOVOU      208(SI), X15
	PXOR       X2, X5
	PXOR       X6, X7
	PXOR       X9, X8
	PXOR       X11, X10
	PXOR       X12, X1
	PXOR       X13, X3
	PXOR       X14, X0
	PXOR       X15, X4
	MOVOU      X5, 0(DX)
	MOVOU      X7, 16(DX)
	MOVOU      X8, 64(DX)
	MOVOU      X10, 80(DX)
	MOVOU      X1, 128(DX)
	MOVOU      X3, 144(DX)
	MOVOU      X0, 192(DX)
	MOVOU      X4, 208(DX)
	MOVO       384(BP), X0
	MOVO       400(BP), X1
	MOVO       416(BP), X2
	MOVO       432(BP), X3
	MOVO       448(BP), X4
	MOVO       464(BP), X5
	MOVO       480(BP), X6
	MOVO       496(BP), X7
	MOVO       X0, X8
	MOVO       X2, X9
	MOVO       X4, X10
	MOVO       X6, X11
	PUNPCKLLQ  X1, X8
	PUNPCKLLQ  X3, X9
	PUNPCKHLQ  X1, X0
	PUNPCKHLQ  X3, X2
	PUNPCKLLQ  X5, X10
	PUNPCKLLQ  X7, X11
	PUNPCKHLQ  X5, X4
	PUNPCKHLQ  X7, X6
	MOVO       X8, X1
	MOVO       X0, X3
	MOVO       X10, X5
	MOVO       X4, X7
	PUNPCKLQDQ X9, X1
	PUNPCKLQDQ X11, X5
	PUNPCKHQDQ X9, X8
	PUNPCKHQDQ X11, X10
	PUNPCKLQDQ X2, X3
	PUNPCKLQDQ X6, X7
	PUNPCKHQDQ X2, X0
	PUNPCKHQDQ X6, X4
	MOVOU      32(SI), X2
	MOVOU      48(SI), X6
	MOVOU      96(SI), X9
	MOVOU      112(SI), X11
	MOVOU      160(SI), X12
	MOVOU      176(SI), X13
	MOVOU      224(SI), X14
	MOVOU      240(SI), X15
	PXOR       X2, X1
	PXOR       X6, X5
	PXOR       X9, X8
	PXOR       X11, X10
	PXOR       X12, X3
	PXOR       X13, X7
	PXOR       X14, X0
	PXOR       X15, X4
	MOVOU      X1, 32(DX)
	MOVOU      X5, 48(DX)
	MOVOU      X8, 96(DX)
	MOVOU      X10, 112(DX)
	MOVOU      X3, 160(DX)
	MOVOU      X7, 176(DX)
	MOVOU      X0, 224(DX)
	MOVOU      X4, 240(DX)
	ADDQ       $256, SI
	JMP        chacha_blocks_ssse3_mainloop_cont

chacha_blocks_ssse3_noinput1:
	MOVOU      X5, 0(DX)
	MOVOU      X7, 16(DX)
	MOVOU      X8, 64(DX)
	MOVOU      X10, 80(DX)
	MOVOU      X1, 128(DX)
	MOVOU      X3, 144(DX)
	MOVOU      X0, 192(DX)
	MOVOU      X4, 208(DX)
	MOVO       384(BP), X0
	MOVO       400(BP), X1
	MOVO       416(BP), X2
	MOVO       432(BP), X3
	MOVO       448(BP), X4
	MOVO       464(BP), X5
	MOVO       480(BP), X6
	MOVO       496(BP), X7
	MOVO       X0, X8
	MOVO       X2, X9
	MOVO       X4, X10
	MOVO       X6, X11
	PUNPCKLLQ  X1, X8
	PUNPCKLLQ  X3, X9
	PUNPCKHLQ  X1, X0
	PUNPCKHLQ  X3, X2
	PUNPCKLLQ  X5, X10
	PUNPCKLLQ  X7, X11
	PUNPCKHLQ  X5, X4
	PUNPCKHLQ  X7, X6
	MOVO       X8, X1
	MOVO       X0, X3
	MOVO       X10, X5
	MOVO       X4, X7
	PUNPCKLQDQ X9, X1
	PUNPCKLQDQ X11, X5
	PUNPCKHQDQ X9, X8
	PUNPCKHQDQ X11, X10
	PUNPCKLQDQ X2, X3
	PUNPCKLQDQ X6, X7
	PUNPCKHQDQ X2, X0
	PUNPCKHQDQ X6, X4
	MOVOU      X1, 32(DX)
	MOVOU      X5, 48(DX)
	MOVOU      X8, 96(DX)
	MOVOU      X10, 112(DX)
	MOVOU      X3, 160(DX)
	MOVOU      X7, 176(DX)
	MOVOU      X0, 224(DX)
	MOVOU      X4, 240(DX)

chacha_blocks_ssse3_mainloop_cont:
	ADDQ $256, DX
	SUBQ $256, CX
	CMPQ CX, $256
	JAE  chacha_blocks_ssse3_atleast256
	MOVO 80(BP), X6
	MOVO 96(BP), X7
	MOVO 0(BP), X8
	MOVO 16(BP), X9
	MOVO 32(BP), X10
	MOVO 48(BP), X11
	MOVQ $1, R9

chacha_blocks_ssse3_below256:
	MOVQ R9, X5
	ANDQ CX, CX
	JZ   chacha_blocks_ssse3_done
	CMPQ CX, $64
	JAE  chacha_blocks_ssse3_above63
	MOVQ DX, R9
	ANDQ SI, SI
	JZ   chacha_blocks_ssse3_noinput2
	MOVQ CX, R10
	MOVQ BP, DX
	ADDQ R10, SI
	ADDQ R10, DX
	NEGQ R10

chacha_blocks_ssse3_copyinput:
	MOVB (SI)(R10*1), AX
	MOVB AX, (DX)(R10*1)
	INCQ R10
	JNZ  chacha_blocks_ssse3_copyinput
	MOVQ BP, SI

chacha_blocks_ssse3_noinput2:
	MOVQ BP, DX

chacha_blocks_ssse3_above63:
	MOVO X8, X0
	MOVO X9, X1
	MOVO X10, X2
	MOVO X11, X3

	// MOVQ 64(BP), AX
	MOVQ $20, AX

chacha_blocks_ssse3_mainloop2:
	PADDD  X1, X0
	PXOR   X0, X3
	PSHUFB X6, X3
	PADDD  X3, X2
	PXOR   X2, X1
	MOVO   X1, X4
	PSLLL  $12, X4
	PSRLL  $20, X1
	PXOR   X4, X1
	PADDD  X1, X0
	PXOR   X0, X3
	PSHUFB X7, X3
	PSHUFD $0x93, X0, X0
	PADDD  X3, X2
	PSHUFD $0x4e, X3, X3
	PXOR   X2, X1
	PSHUFD $0x39, X2, X2
	MOVO   X1, X4
	PSLLL  $7, X4
	PSRLL  $25, X1
	PXOR   X4, X1
	PADDD  X1, X0
	PXOR   X0, X3
	PSHUFB X6, X3
	PADDD  X3, X2
	PXOR   X2, X1
	MOVO   X1, X4
	PSLLL  $12, X4
	PSRLL  $20, X1
	PXOR   X4, X1
	PADDD  X1, X0
	PXOR   X0, X3
	PSHUFB X7, X3
	PSHUFD $0x39, X0, X0
	PADDD  X3, X2
	PSHUFD $0x4e, X3, X3
	PXOR   X2, X1
	PSHUFD $0x93, X2, X2
	MOVO   X1, X4
	PSLLL  $7, X4
	PSRLL  $25, X1
	PXOR   X4, X1
	SUBQ   $2, AX
	JNZ    chacha_blocks_ssse3_mainloop2
	PADDD  X8, X0
	PADDD  X9, X1
	PADDD  X10, X2
	PADDD  X11, X3
	ANDQ   SI, SI
	JZ     chacha_blocks_ssse3_noinput3
	MOVOU  0(SI), X12
	MOVOU  16(SI), X13
	MOVOU  32(SI), X14
	MOVOU  48(SI), X15
	PXOR   X12, X0
	PXOR   X13, X1
	PXOR   X14, X2
	PXOR   X15, X3
	ADDQ   $64, SI

chacha_blocks_ssse3_noinput3:
	MOVOU X0, 0(DX)
	MOVOU X1, 16(DX)
	MOVOU X2, 32(DX)
	MOVOU X3, 48(DX)
	PADDQ X5, X11
	CMPQ  CX, $64
	JBE   chacha_blocks_ssse3_mainloop2_finishup
	ADDQ  $64, DX
	SUBQ  $64, CX
	JMP   chacha_blocks_ssse3_below256

chacha_blocks_ssse3_mainloop2_finishup:
	CMPQ CX, $64
	JE   chacha_blocks_ssse3_done
	ADDQ CX, R9
	ADDQ CX, DX
	NEGQ CX

chacha_blocks_ssse3_copyoutput:
	MOVB (DX)(CX*1), AX
	MOVB AX, (R9)(CX*1)
	INCQ CX
	JNZ  chacha_blocks_ssse3_copyoutput

chacha_blocks_ssse3_done:
	MOVOU X11, 32(DI)

	RET

// func hChaChaSSSE3(key, nonce []byte, dst *byte)
TEXT ·hChaChaSSSE3(SB), NOSPLIT|NOFRAME, $0-56
	MOVQ key+0(FP), DI
	MOVQ nonce+24(FP), SI
	MOVQ dst+48(FP), DX

	MOVL $20, CX

	LEAQ ·chacha_constants<>(SB), AX
	MOVO 0(AX), X0
	MOVO 16(AX), X5
	MOVO 32(AX), X6

	MOVOU 0(DI), X1
	MOVOU 16(DI), X2
	MOVOU 0(SI), X3

hchacha_ssse3_mainloop:
	PADDD  X1, X0
	PXOR   X0, X3
	PSHUFB X5, X3
	PADDD  X3, X2
	PXOR   X2, X1
	MOVO   X1, X4
	PSLLL  $12, X1
	PSRLL  $20, X4
	PXOR   X4, X1
	PADDD  X1, X0
	PXOR   X0, X3
	PSHUFB X6, X3
	PSHUFD $0X93, X0, X0
	PADDD  X3, X2
	PSHUFD $0X4E, X3, X3
	PXOR   X2, X1
	PSHUFD $0X39, X2, X2
	MOVO   X1, X4
	PSLLL  $7, X1
	PSRLL  $25, X4
	PXOR   X4, X1
	SUBQ   $2, CX
	PADDD  X1, X0
	PXOR   X0, X3
	PSHUFB X5, X3
	PADDD  X3, X2
	PXOR   X2, X1
	MOVO   X1, X4
	PSLLL  $12, X1
	PSRLL  $20, X4
	PXOR   X4, X1
	PADDD  X1, X0
	PXOR   X0, X3
	PSHUFB X6, X3
	PSHUFD $0X39, X0, X0
	PADDD  X3, X2
	PSHUFD $0X4E, X3, X3
	PXOR   X2, X1
	PSHUFD $0X93, X2, X2
	MOVO   X1, X4
	PSLLL  $7, X1
	PSRLL  $25, X4
	PXOR   X4, X1
	JA     hchacha_ssse3_mainloop

	MOVOU X0, 0(DX)
	MOVOU X3, 16(DX)

	RET
