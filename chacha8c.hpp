// portions Copyright 2026 Jason E. Aten, Ph.D. All rights reserved.
// portions Copyright 2023 The Go Authors. All rights reserved.
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

#ifndef CHACHA8C_HPP
#define CHACHA8C_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <limits>
#include <climits>

namespace chacha8c {

static constexpr std::size_t key_size = 32;
static constexpr std::size_t block_size = 64;

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

static constexpr std::uint32_t j0 = 0x61707865u;
static constexpr std::uint32_t j1 = 0x3320646eu;
static constexpr std::uint32_t j2 = 0x79622d32u;
static constexpr std::uint32_t j3 = 0x6b206574u;

inline std::uint32_t load32_le(const std::uint8_t *p) noexcept
{
	return static_cast<std::uint32_t>(p[0]) |
	       (static_cast<std::uint32_t>(p[1]) << 8) |
	       (static_cast<std::uint32_t>(p[2]) << 16) |
	       (static_cast<std::uint32_t>(p[3]) << 24);
}

inline std::uint64_t load64_le(const std::uint8_t *p) noexcept
{
	return static_cast<std::uint64_t>(load32_le(p)) |
	       (static_cast<std::uint64_t>(load32_le(p + 4)) << 32);
}

inline void store32_le(std::uint8_t *p, std::uint32_t x) noexcept
{
	p[0] = static_cast<std::uint8_t>(x);
	p[1] = static_cast<std::uint8_t>(x >> 8);
	p[2] = static_cast<std::uint8_t>(x >> 16);
	p[3] = static_cast<std::uint8_t>(x >> 24);
}

inline void store64_le(std::uint8_t *p, std::uint64_t x) noexcept
{
	store32_le(p, static_cast<std::uint32_t>(x));
	store32_le(p + 4, static_cast<std::uint32_t>(x >> 32));
}

namespace detail {

inline std::uint32_t rotl32(std::uint32_t x, unsigned int n) noexcept
{
	return (x << n) | (x >> (32 - n));
}

inline void quarter_round(std::uint32_t &a,
                          std::uint32_t &b,
                          std::uint32_t &c,
                          std::uint32_t &d) noexcept
{
	a += b;
	d ^= a;
	d = rotl32(d, 16);
	c += d;
	b ^= c;
	b = rotl32(b, 12);
	a += b;
	d ^= a;
	d = rotl32(d, 8);
	c += d;
	b ^= c;
	b = rotl32(b, 7);
}

static constexpr std::uint32_t ctr_inc = 4;
static constexpr std::uint32_t ctr_max = 16;
static constexpr std::uint32_t chunk = 32;
static constexpr std::uint32_t reseed = 4;

struct chacha8rand_state {
	std::uint64_t buf[chunk];
	std::uint64_t seed[4];
	std::uint32_t i;
	std::uint32_t n;
	std::uint32_t c;
};

inline void setup(const std::uint64_t seed[4],
                  std::uint32_t b[16][4],
                  std::uint32_t counter) noexcept
{
	for (std::size_t lane = 0; lane < 4; lane++) {
		b[0][lane] = j0;
		b[1][lane] = j1;
		b[2][lane] = j2;
		b[3][lane] = j3;
		b[4][lane] = static_cast<std::uint32_t>(seed[0]);
		b[5][lane] = static_cast<std::uint32_t>(seed[0] >> 32);
		b[6][lane] = static_cast<std::uint32_t>(seed[1]);
		b[7][lane] = static_cast<std::uint32_t>(seed[1] >> 32);
		b[8][lane] = static_cast<std::uint32_t>(seed[2]);
		b[9][lane] = static_cast<std::uint32_t>(seed[2] >> 32);
		b[10][lane] = static_cast<std::uint32_t>(seed[3]);
		b[11][lane] = static_cast<std::uint32_t>(seed[3] >> 32);
		b[12][lane] = counter + static_cast<std::uint32_t>(lane);
		b[13][lane] = 0;
		b[14][lane] = 0;
		b[15][lane] = 0;
	}
}

inline void block(const std::uint64_t seed[4],
                  std::uint64_t buf[chunk],
                  std::uint32_t counter) noexcept
{
	std::uint32_t b[16][4];

	setup(seed, b, counter);

	for (std::size_t lane = 0; lane < 4; lane++) {
		std::uint32_t b0 = b[0][lane];
		std::uint32_t b1 = b[1][lane];
		std::uint32_t b2 = b[2][lane];
		std::uint32_t b3 = b[3][lane];
		std::uint32_t b4 = b[4][lane];
		std::uint32_t b5 = b[5][lane];
		std::uint32_t b6 = b[6][lane];
		std::uint32_t b7 = b[7][lane];
		std::uint32_t b8 = b[8][lane];
		std::uint32_t b9 = b[9][lane];
		std::uint32_t b10 = b[10][lane];
		std::uint32_t b11 = b[11][lane];
		std::uint32_t b12 = b[12][lane];
		std::uint32_t b13 = b[13][lane];
		std::uint32_t b14 = b[14][lane];
		std::uint32_t b15 = b[15][lane];

		for (int round = 0; round < 4; round++) {
			quarter_round(b0, b4, b8, b12);
			quarter_round(b1, b5, b9, b13);
			quarter_round(b2, b6, b10, b14);
			quarter_round(b3, b7, b11, b15);

			quarter_round(b0, b5, b10, b15);
			quarter_round(b1, b6, b11, b12);
			quarter_round(b2, b7, b8, b13);
			quarter_round(b3, b4, b9, b14);
		}

		b[0][lane] = b0;
		b[1][lane] = b1;
		b[2][lane] = b2;
		b[3][lane] = b3;
		b[4][lane] += b4;
		b[5][lane] += b5;
		b[6][lane] += b6;
		b[7][lane] += b7;
		b[8][lane] += b8;
		b[9][lane] += b9;
		b[10][lane] += b10;
		b[11][lane] += b11;
		b[12][lane] = b12;
		b[13][lane] = b13;
		b[14][lane] = b14;
		b[15][lane] = b15;
	}

	for (std::size_t word = 0; word < 16; word++) {
		buf[word * 2 + 0] = static_cast<std::uint64_t>(b[word][0]) |
		                     (static_cast<std::uint64_t>(b[word][1]) << 32);
		buf[word * 2 + 1] = static_cast<std::uint64_t>(b[word][2]) |
		                     (static_cast<std::uint64_t>(b[word][3]) << 32);
	}
}

inline void init(chacha8rand_state &s, const std::uint8_t seed[key_size]) noexcept
{
	s.seed[0] = load64_le(seed + 0 * 8);
	s.seed[1] = load64_le(seed + 1 * 8);
	s.seed[2] = load64_le(seed + 2 * 8);
	s.seed[3] = load64_le(seed + 3 * 8);
	block(s.seed, s.buf, 0);
	s.c = 0;
	s.i = 0;
	s.n = chunk;
}

inline bool next(chacha8rand_state &s, std::uint64_t &out) noexcept
{
	std::uint32_t i = s.i;

	if (i >= s.n) {
		return false;
	}
	s.i = i + 1;
	out = s.buf[i & 31u];
	return true;
}

inline void refill(chacha8rand_state &s) noexcept
{
	s.c += ctr_inc;
	if (s.c == ctr_max) {
		s.seed[0] = s.buf[chunk - reseed + 0];
		s.seed[1] = s.buf[chunk - reseed + 1];
		s.seed[2] = s.buf[chunk - reseed + 2];
		s.seed[3] = s.buf[chunk - reseed + 3];
		s.c = 0;
	}
	block(s.seed, s.buf, s.c);
	s.i = 0;
	s.n = chunk;
	if (s.c == ctr_max - ctr_inc) {
		s.n = chunk - reseed;
	}
}

} // namespace detail

constexpr int ExpectedRandMax = 2147483647;

static_assert(
    RAND_MAX == ExpectedRandMax,
    "Unsupported platform: RAND_MAX is not 2147483647"
);
static_assert(
    sizeof(int) * CHAR_BIT >= 32,
    "This Rand() implementation requires int to be at least 32 bits"
);

class ChaCha8 {
public:
	explicit ChaCha8(const std::uint8_t seed[key_size]) noexcept
	{
		Seed(seed);
	}
	ChaCha8() noexcept {}

	void Seed(const std::uint8_t seed[key_size]) noexcept
	{
		detail::init(state_, seed);
		std::memset(read_buf_, 0, sizeof(read_buf_));
		read_len_ = 0;
	}

	std::uint64_t Uint64() noexcept
	{
		std::uint64_t x;

		for (;;) {
			if (detail::next(state_, x)) {
				return x;
			}
			detail::refill(state_);
		}
	}

        // like <random>'s rand(), returns a number in [0, RAND_MAX] inclusive.
        int Rand() noexcept {
            return static_cast<int>(Uint64() >> 33);
        }

	std::size_t Read(std::uint8_t *p, std::size_t len) noexcept
	{
		std::size_t n = 0;

		if (read_len_ > 0) {
			std::size_t take = len < read_len_ ? len : read_len_;

			std::memcpy(p, read_buf_ + sizeof(read_buf_) - read_len_, take);
			read_len_ -= take;
			p += take;
			len -= take;
			n += take;
		}

		while (len >= 8) {
			store64_le(p, Uint64());
			p += 8;
			len -= 8;
			n += 8;
		}

		if (len > 0) {
			store64_le(read_buf_, Uint64());
			std::memcpy(p, read_buf_, len);
			read_len_ = 8 - len;
			n += len;
		}

		return n;
	}

private:
	detail::chacha8rand_state state_;
	std::uint8_t read_buf_[8];
	std::size_t read_len_;
};

inline ChaCha8 NewChaCha8(const std::uint8_t seed[key_size]) noexcept
{
	return ChaCha8(seed);
}

} // namespace chacha8c

#endif
