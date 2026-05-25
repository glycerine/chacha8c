// Copyright 2016 The Go Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google LLC nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Copyright (c) 2020
// The C2SP Authors.  All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// THIS SOFTWARE IS PROVIDED BY The C2SP Authors ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL The C2SP Authors BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.

// origin: https://github.com/C2SP/C2SP/raw/refs/heads/main/chacha8rand/chacha8rand.go

package main

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"unsafe"
)

const goarchBigEndian = false

func main() {
	input := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
	var uints []uint64
	for i := 0; i < 3; i++ {
		var output []byte
		stream := make([]byte, 1024)
		OneshotChaCha8(input, stream)
		for i := uint32(0); i < 16; i++ {
			binary.LittleEndian.PutUint32(stream[i*64+0*4:], binary.LittleEndian.Uint32(stream[i*64+0*4:])-0x61707865)
			binary.LittleEndian.PutUint32(stream[i*64+1*4:], binary.LittleEndian.Uint32(stream[i*64+1*4:])-0x3320646e)
			binary.LittleEndian.PutUint32(stream[i*64+2*4:], binary.LittleEndian.Uint32(stream[i*64+2*4:])-0x79622d32)
			binary.LittleEndian.PutUint32(stream[i*64+3*4:], binary.LittleEndian.Uint32(stream[i*64+3*4:])-0x6b206574)
			binary.LittleEndian.PutUint32(stream[i*64+12*4:], binary.LittleEndian.Uint32(stream[i*64+12*4:])-i)
		}
		for b := 0; b < 16; b += 4 {
			for i := 0; i < 64; i += 4 {
				output = append(output, stream[0*64+i:0*64+i+4]...)
				output = append(output, stream[1*64+i:1*64+i+4]...)
				output = append(output, stream[2*64+i:2*64+i+4]...)
				output = append(output, stream[3*64+i:3*64+i+4]...)
			}
			stream = stream[256:]
		}
		copy(input, output[1024-32:])
		output = output[:1024-32]
		for i := 0; i < len(output); i += 8 {
			uints = append(uints, binary.LittleEndian.Uint64(output[i:]))
		}
		for len(output) > 0 {
			fmt.Printf("%x\n", output[:32])
			output = output[32:]
		}
	}
	for i, n := range uints {
		if i%4 == 0 {
			fmt.Printf("\n")
		}
		fmt.Printf("%#016x, ", n)
	}
}

// Oneshot starts over each time with key and the j constants as initial state.
func OneshotChaCha8(key, dst []byte) {
	k := [8]uint32{
		binary.LittleEndian.Uint32(key[0:4]),
		binary.LittleEndian.Uint32(key[4:8]),
		binary.LittleEndian.Uint32(key[8:12]),
		binary.LittleEndian.Uint32(key[12:16]),
		binary.LittleEndian.Uint32(key[16:20]),
		binary.LittleEndian.Uint32(key[20:24]),
		binary.LittleEndian.Uint32(key[24:28]),
		binary.LittleEndian.Uint32(key[28:32]),
	}

	// To generate each block of key stream, the initial cipher state
	// (represented below) is passed through 8 rounds of shuffling,
	// alternatively applying quarterRounds by columns (like 1, 5, 9, 13)
	// or by diagonals (like 1, 6, 11, 12).
	//
	//      0:cccccccc   1:cccccccc   2:cccccccc   3:cccccccc
	//      4:kkkkkkkk   5:kkkkkkkk   6:kkkkkkkk   7:kkkkkkkk
	//      8:kkkkkkkk   9:kkkkkkkk  10:kkkkkkkk  11:kkkkkkkk
	//     12:bbbbbbbb  13:nnnnnnnn  14:nnnnnnnn  15:nnnnnnnn
	//
	//            c=constant k=key b=blockcount n=nonce
	var (
		c0, c1, c2, c3     = j0, j1, j2, j3
		c4, c5, c6, c7     = k[0], k[1], k[2], k[3]
		c8, c9, c10, c11   = k[4], k[5], k[6], k[7]
		c12, c13, c14, c15 = uint32(0), uint32(0), uint32(0), uint32(0)
	)

	// Three quarters of the first round don't depend on the counter, so we can
	// calculate them here, and reuse them for multiple blocks in the loop.
	p1, p5, p9, p13 := quarterRound(c1, c5, c9, c13)
	p2, p6, p10, p14 := quarterRound(c2, c6, c10, c14)
	p3, p7, p11, p15 := quarterRound(c3, c7, c11, c15)

	for len(dst) >= 64 {
		// The remainder of the first column round.
		fcr0, fcr4, fcr8, fcr12 := quarterRound(c0, c4, c8, c12)

		// The second diagonal round.
		x0, x5, x10, x15 := quarterRound(fcr0, p5, p10, p15)
		x1, x6, x11, x12 := quarterRound(p1, p6, p11, fcr12)
		x2, x7, x8, x13 := quarterRound(p2, p7, fcr8, p13)
		x3, x4, x9, x14 := quarterRound(p3, fcr4, p9, p14)

		// The remaining 6 rounds.
		for i := 0; i < 3; i++ {
			// Column round.
			x0, x4, x8, x12 = quarterRound(x0, x4, x8, x12)
			x1, x5, x9, x13 = quarterRound(x1, x5, x9, x13)
			x2, x6, x10, x14 = quarterRound(x2, x6, x10, x14)
			x3, x7, x11, x15 = quarterRound(x3, x7, x11, x15)

			// Diagonal round.
			x0, x5, x10, x15 = quarterRound(x0, x5, x10, x15)
			x1, x6, x11, x12 = quarterRound(x1, x6, x11, x12)
			x2, x7, x8, x13 = quarterRound(x2, x7, x8, x13)
			x3, x4, x9, x14 = quarterRound(x3, x4, x9, x14)
		}

		// Add back the initial state to generate the key stream.
		binary.LittleEndian.PutUint32(dst[0:4], x0+c0)
		binary.LittleEndian.PutUint32(dst[4:8], x1+c1)
		binary.LittleEndian.PutUint32(dst[8:12], x2+c2)
		binary.LittleEndian.PutUint32(dst[12:16], x3+c3)
		binary.LittleEndian.PutUint32(dst[16:20], x4+c4)
		binary.LittleEndian.PutUint32(dst[20:24], x5+c5)
		binary.LittleEndian.PutUint32(dst[24:28], x6+c6)
		binary.LittleEndian.PutUint32(dst[28:32], x7+c7)
		binary.LittleEndian.PutUint32(dst[32:36], x8+c8)
		binary.LittleEndian.PutUint32(dst[36:40], x9+c9)
		binary.LittleEndian.PutUint32(dst[40:44], x10+c10)
		binary.LittleEndian.PutUint32(dst[44:48], x11+c11)
		binary.LittleEndian.PutUint32(dst[48:52], x12+c12)
		binary.LittleEndian.PutUint32(dst[52:56], x13+c13)
		binary.LittleEndian.PutUint32(dst[56:60], x14+c14)
		binary.LittleEndian.PutUint32(dst[60:64], x15+c15)

		c12 += 1

		dst = dst[64:]
	}
}

// Q: what are these j0, j1, j2, j3 constants?
// A: They are part of the ChaCha family definition, not arbitrary Go choices.
//
// Those four words are the standard ChaCha constants for a 256-bit key:
//
// 0x61707865  // "expa"
// 0x3320646e  // "nd 3"
// 0x79622d32  // "2-by"
// 0x6b206574  // "te k"
// Interpreted as little-endian bytes, together they spell:
//
// "expand 32-byte k"
// ChaCha8 uses the same initial state layout and
// constants as ChaCha20; the "8" only means 8 rounds
// instead of 20. So these constants are part of the
// algorithm's state initialization for the 32-byte-key variant.
//
// One nuance: in the Go demo main, those constants are
// subtracted back out of the first four output words
// after ChaCha8(...). That subtraction is not normal
// ChaCha keystream generation; it is part of that
// specific test/demo transform. But the constants
// themselves are canonical ChaCha constants.

// The constant first 4 words of the ChaCha8 state.
const (
	j0 uint32 = 0x61707865 // expa
	j1 uint32 = 0x3320646e // nd 3
	j2 uint32 = 0x79622d32 // 2-by
	j3 uint32 = 0x6b206574 // te k
)

// quarterRound is the core of ChaCha8. It shuffles the bits of 4 state words.
// It's executed 4 times for each of the 8 ChaCha8 rounds, operating on all 16
// words each round, in columnar or diagonal groups of 4 at a time.
func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 16)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 12)
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 8)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 7)
	return a, b, c, d
}

type ChaCha8 struct {
	state chacha8randState

	// The last readLen bytes of readBuf are still to be consumed by Read.
	readBuf [8]byte
	readLen int // 0 <= readLen <= 8
}

// A State holds the state for a single random generator.
// It must be used from one goroutine at a time.
// If used by multiple goroutines at a time, the goroutines
// may see the same random values, but the code will not
// crash or cause out-of-bounds memory accesses.
type chacha8randState struct {
	buf  [32]uint64
	seed [4]uint64
	i    uint32
	n    uint32
	c    uint32
}

const (
	ctrInc = 4  // increment counter by 4 between block calls
	ctrMax = 16 // reseed when counter reaches 16
	chunk  = 32 // each chunk produced by block is 32 uint64s
	reseed = 4  // reseed with 4 words
)

// block is the chacha8rand block function. See block_generic below.
//func block(seed *[4]uint64, blocks *[32]uint64, counter uint32)

// Next returns the next random value, along with a boolean
// indicating whether one was available.
// If one is not available, the caller should call Refill
// and then repeat the call to Next.
//
// Next is //go:nosplit to allow its use in the runtime
// with per-m data without holding the per-m lock.
//
//go:nosplit
func (s *chacha8randState) Next() (uint64, bool) {
	i := s.i
	if i >= s.n {
		return 0, false
	}
	s.i = i + 1
	return s.buf[i&31], true // i&31 eliminates bounds check
}

// Init seeds the State with the given seed value.
func (s *chacha8randState) Init(seed [32]byte) {
	s.Init64([4]uint64{
		leUint64(seed[0*8:]),
		leUint64(seed[1*8:]),
		leUint64(seed[2*8:]),
		leUint64(seed[3*8:]),
	})
}

func leUint64(b []byte) uint64 {
	_ = b[7] // bounds check hint to compiler; see golang.org/issue/14808
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

// Init64 seeds the state with the given seed value.
func (s *chacha8randState) Init64(seed [4]uint64) {
	s.seed = seed
	block_generic(&s.seed, &s.buf, 0)
	s.c = 0
	s.i = 0
	s.n = chunk
}

// Refill refills the state with more random values.
// After a call to Refill, an immediate call to Next will succeed
// (unless multiple goroutines are incorrectly sharing a state).
func (s *chacha8randState) Refill() {
	s.c += ctrInc
	if s.c == ctrMax {
		// Reseed with generated uint64s for forward secrecy.
		// Normally this is done immediately after computing a block,
		// but we do it immediately before computing the next block,
		// to allow a much smaller serialized state (just the seed plus offset).
		// This gives a delayed benefit for the forward secrecy
		// (you can reconstruct the recent past given a memory dump),
		// which we deem acceptable in exchange for the reduced size.
		s.seed[0] = s.buf[len(s.buf)-reseed+0]
		s.seed[1] = s.buf[len(s.buf)-reseed+1]
		s.seed[2] = s.buf[len(s.buf)-reseed+2]
		s.seed[3] = s.buf[len(s.buf)-reseed+3]
		s.c = 0
	}
	block_generic(&s.seed, &s.buf, s.c)
	s.i = 0
	s.n = uint32(len(s.buf))
	if s.c == ctrMax-ctrInc {
		s.n = uint32(len(s.buf)) - reseed
	}
}

// Reseed reseeds the state with new random values.
// After a call to Reseed, any previously returned random values
// have been erased from the memory of the state and cannot be
// recovered.
func (s *chacha8randState) Reseed() {
	var seed [4]uint64
	for i := range seed {
		for {
			x, ok := s.Next()
			if ok {
				seed[i] = x
				break
			}
			s.Refill()
		}
	}
	s.Init64(seed)
}

// NewChaCha8 returns a new ChaCha8 seeded with the given seed.
func NewChaCha8(seed [32]byte) *ChaCha8 {
	c := new(ChaCha8)
	c.state.Init(seed)
	return c
}

// Seed resets the ChaCha8 to behave the same way as NewChaCha8(seed).
func (c *ChaCha8) Seed(seed [32]byte) {
	c.state.Init(seed)
	c.readLen = 0
	c.readBuf = [8]byte{}
}

// Uint64 returns a uniformly distributed random uint64 value.
func (c *ChaCha8) Uint64() uint64 {
	for {
		x, ok := c.state.Next()
		if ok {
			return x
		}
		c.state.Refill()
	}
}

// Read reads exactly len(p) bytes into p.
// It always returns len(p) and a nil error.
//
// If calls to Read and Uint64 are interleaved, the order in which bits are
// returned by the two is undefined, and Read may return bits generated before
// the last call to Uint64.
func (c *ChaCha8) Read(p []byte) (n int, err error) {
	if c.readLen > 0 {
		n = copy(p, c.readBuf[len(c.readBuf)-c.readLen:])
		c.readLen -= n
		p = p[n:]
	}
	for len(p) >= 8 {
		lePutUint64(p, c.Uint64())
		p = p[8:]
		n += 8
	}
	if len(p) > 0 {
		lePutUint64(c.readBuf[:], c.Uint64())
		n += copy(p, c.readBuf[:])
		c.readLen = 8 - len(p)
	}
	return
}

func lePutUint64(b []byte, v uint64) {
	_ = b[7] // early bounds check to guarantee safety of writes below
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
}

// block_generic is the non-assembly block implementation,
// for use on systems without special assembly.
// Even on such systems, it is quite fast: on GOOS=386,
// ChaCha8 using this code generates random values faster than PCG-DXSM.
func block_generic(seed *[4]uint64, buf *[32]uint64, counter uint32) {
	b := (*[16][4]uint32)(unsafe.Pointer(buf))

	setup(seed, b, counter)

	for i := range b[0] {
		// Load block i from b[*][i] into local variables.
		b0 := b[0][i]
		b1 := b[1][i]
		b2 := b[2][i]
		b3 := b[3][i]
		b4 := b[4][i]
		b5 := b[5][i]
		b6 := b[6][i]
		b7 := b[7][i]
		b8 := b[8][i]
		b9 := b[9][i]
		b10 := b[10][i]
		b11 := b[11][i]
		b12 := b[12][i]
		b13 := b[13][i]
		b14 := b[14][i]
		b15 := b[15][i]

		// 4 iterations of eight quarter-rounds each is 8 rounds
		for round := 0; round < 4; round++ {
			b0, b4, b8, b12 = qr(b0, b4, b8, b12)
			b1, b5, b9, b13 = qr(b1, b5, b9, b13)
			b2, b6, b10, b14 = qr(b2, b6, b10, b14)
			b3, b7, b11, b15 = qr(b3, b7, b11, b15)

			b0, b5, b10, b15 = qr(b0, b5, b10, b15)
			b1, b6, b11, b12 = qr(b1, b6, b11, b12)
			b2, b7, b8, b13 = qr(b2, b7, b8, b13)
			b3, b4, b9, b14 = qr(b3, b4, b9, b14)
		}

		// Store block i back into b[*][i].
		// Add b4..b11 back to the original key material,
		// like in ChaCha20, to avoid trivial invertibility.
		// There is no entropy in b0..b3 and b12..b15
		// so we can skip the additions and save some time.
		b[0][i] = b0
		b[1][i] = b1
		b[2][i] = b2
		b[3][i] = b3
		b[4][i] += b4
		b[5][i] += b5
		b[6][i] += b6
		b[7][i] += b7
		b[8][i] += b8
		b[9][i] += b9
		b[10][i] += b10
		b[11][i] += b11
		b[12][i] = b12
		b[13][i] = b13
		b[14][i] = b14
		b[15][i] = b15
	}

	if goarchBigEndian {
		// On a big-endian system, reading the uint32 pairs as uint64s
		// will word-swap them compared to little-endian, so we word-swap
		// them here first to make the next swap get the right answer.
		for i, x := range buf {
			buf[i] = x>>32 | x<<32
		}
	}
}

// qr is the (inlinable) ChaCha8 quarter round.
func qr(a, b, c, d uint32) (_a, _b, _c, _d uint32) {
	a += b
	d ^= a
	d = d<<16 | d>>16
	c += d
	b ^= c
	b = b<<12 | b>>20
	a += b
	d ^= a
	d = d<<8 | d>>24
	c += d
	b ^= c
	b = b<<7 | b>>25
	return a, b, c, d
}

// setup sets up 4 ChaCha8 blocks in b32 with the counter and seed.
// Note that b32 is [16][4]uint32 not [4][16]uint32: the blocks are interlaced
// the same way they would be in a 4-way SIMD implementations.
func setup(seed *[4]uint64, b32 *[16][4]uint32, counter uint32) {
	// Convert to uint64 to do half as many stores to memory.
	b := (*[16][2]uint64)(unsafe.Pointer(b32))

	// Constants; same as in ChaCha20: "expand 32-byte k"
	b[0][0] = 0x61707865_61707865
	b[0][1] = 0x61707865_61707865

	b[1][0] = 0x3320646e_3320646e
	b[1][1] = 0x3320646e_3320646e

	b[2][0] = 0x79622d32_79622d32
	b[2][1] = 0x79622d32_79622d32

	b[3][0] = 0x6b206574_6b206574
	b[3][1] = 0x6b206574_6b206574

	// Seed values.
	var x64 uint64
	var x uint32

	x = uint32(seed[0])
	x64 = uint64(x)<<32 | uint64(x)
	b[4][0] = x64
	b[4][1] = x64

	x = uint32(seed[0] >> 32)
	x64 = uint64(x)<<32 | uint64(x)
	b[5][0] = x64
	b[5][1] = x64

	x = uint32(seed[1])
	x64 = uint64(x)<<32 | uint64(x)
	b[6][0] = x64
	b[6][1] = x64

	x = uint32(seed[1] >> 32)
	x64 = uint64(x)<<32 | uint64(x)
	b[7][0] = x64
	b[7][1] = x64

	x = uint32(seed[2])
	x64 = uint64(x)<<32 | uint64(x)
	b[8][0] = x64
	b[8][1] = x64

	x = uint32(seed[2] >> 32)
	x64 = uint64(x)<<32 | uint64(x)
	b[9][0] = x64
	b[9][1] = x64

	x = uint32(seed[3])
	x64 = uint64(x)<<32 | uint64(x)
	b[10][0] = x64
	b[10][1] = x64

	x = uint32(seed[3] >> 32)
	x64 = uint64(x)<<32 | uint64(x)
	b[11][0] = x64
	b[11][1] = x64

	// Counters.
	if goarch.BigEndian {
		b[12][0] = uint64(counter+0)<<32 | uint64(counter+1)
		b[12][1] = uint64(counter+2)<<32 | uint64(counter+3)
	} else {
		b[12][0] = uint64(counter+0) | uint64(counter+1)<<32
		b[12][1] = uint64(counter+2) | uint64(counter+3)<<32
	}

	// Zeros.
	b[13][0] = 0
	b[13][1] = 0
	b[14][0] = 0
	b[14][1] = 0

	b[15][0] = 0
	b[15][1] = 0
}
