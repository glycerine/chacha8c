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

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/bits"
	mathrand2 "math/rand/v2"
	"unsafe"
)

const goarchBigEndian = false

var _ = mathrand2.NewChaCha8

func main() {
	var seed [32]byte
	copy(seed[:], "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")

	// these match now:
	//rng := NewChaCha8(seed)
	rng := mathrand2.NewChaCha8(seed)

	var uints []uint64
	for i := 0; i < 3; i++ {
		// Each 16-block cycle keeps the final 32 bytes as the next seed.
		output := make([]byte, 1024-32)
		rng.Read(output)

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

	for i := range 100 {
		fmt.Printf("UnbiasedChoice(%v) -> %v\n", i, UnbiasedChoice(rng, int64(i)))
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

// surface the standard library's math/rand/v2 ChaCha8 to make porting to C easier.
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

// block is the chacha8rand block function. See block_generic below instead,
// since we are eschewing assembly.
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

// Rand emulates C rand() from <random> in returning a non-negative
// integer in the range of [0, 2147483647] inclusive. In other
// words we assume a RAND_MAX of 2147483647. For this
// value of RAND_MAX our implementation is fast and has no modulo bias.
func (c *ChaCha8) Rand() int32 {
	return int32(c.Uint64() >> 33)
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
	if goarchBigEndian {
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

// UnbiasedChoice avoids modulo bias when choosing a non-negative
// integer from among nChoices. If nChoices <= 1 we always return 0.
//
// In the Go standard library "math/rand/v2", Rand.IntN() and Rand.Uint64N()
// are similar, but use Lemire-style multiply-high reduction before rejection sampling.
//
// The Go standard library documentation makes no claims about these
// methods being unbiased, although we infer from the internal comments
// that this did appear to be the intent at some point in development.
//
// We can only conclude that nobody was able to prove those implementations
// actually are unbiased and uniform -- or else they would be clearly marked
// and claimed as such -- since this is a critical property in many circumstances.
//
// Hence we prefer UnbiasedChoice when uniformity and lack of bias matters.
func UnbiasedChoice(rngReader io.Reader, nChoices int64) (r int64) {
	if nChoices <= 1 {
		return 0
	}

	b := make([]byte, 8)
	if nChoices == math.MaxInt64 {
		rngReader.Read(b)
		r = int64(binary.LittleEndian.Uint64(b))
		if r < 0 {
			if r == math.MinInt64 {
				return 0
			}
			r = -r
		}
		return r
	}

	// compute the last valid acceptable value,
	// possibly leaving a small window at the top of the
	// int64 range that will require drawing again.
	// we will accept all values <= redrawAbove and
	// modulo them by nChoices.
	redrawAbove := math.MaxInt64 - (((math.MaxInt64 % nChoices) + 1) % nChoices)
	// INVAR: redrawAbove % nChoices == (nChoices - 1).

	for {
		rngReader.Read(b)
		r = int64(binary.LittleEndian.Uint64(b))
		if r < 0 {
			// there is 1 more negative integer than
			// positive integers in 2's complement
			// representation on integers, so the probability
			// is exactly 1/2 of entering here.
			//
			// Does this not bias
			// against 0 though? Yep.
			//
			// Without this next check,
			// 0 has probability 1/2^64. Whereas
			// every other positive integer has
			// probability 2/2^64... So
			// without this next line we are
			// (very subtly) biased against zero.
			// To correct that, we
			// give 0 one more chance by
			// letting it have the last negative
			// number too, which we never
			// want to return anyway.
			if r == math.MinInt64 {
				return 0
			}
			r = -r
		}
		if r > redrawAbove {
			continue
		}
		return r % nChoices
	}
	// never reached. just keep the compiler happy.
	return r
}
