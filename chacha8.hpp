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
//
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

#ifndef CHACHA8_HPP
#define CHACHA8_HPP

#include <cstddef>
#include <cstdint>

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
//
// One nuance: in the Go demo main, those constants are
// subtracted back out of the first four output words
// after ChaCha8(...). That subtraction is not normal
// ChaCha keystream generation; it is part of that 
// specific test/demo transform. But the constants
// themselves are canonical ChaCha constants.

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

} // namespace detail

inline void chacha8(const std::uint8_t key[key_size],
                    std::uint8_t *dst,
                    std::size_t dst_len) noexcept
{
	std::uint32_t k[8];
	std::uint32_t c0 = j0;
	std::uint32_t c1 = j1;
	std::uint32_t c2 = j2;
	std::uint32_t c3 = j3;
	std::uint32_t c12 = 0;
	std::uint32_t c13 = 0;
	std::uint32_t c14 = 0;
	std::uint32_t c15 = 0;

	for (std::size_t i = 0; i < 8; i++) {
		k[i] = load32_le(key + i * 4);
	}

	std::uint32_t c4 = k[0];
	std::uint32_t c5 = k[1];
	std::uint32_t c6 = k[2];
	std::uint32_t c7 = k[3];
	std::uint32_t c8 = k[4];
	std::uint32_t c9 = k[5];
	std::uint32_t c10 = k[6];
	std::uint32_t c11 = k[7];

	std::uint32_t p1 = c1;
	std::uint32_t p5 = c5;
	std::uint32_t p9 = c9;
	std::uint32_t p13 = c13;
	detail::quarter_round(p1, p5, p9, p13);

	std::uint32_t p2 = c2;
	std::uint32_t p6 = c6;
	std::uint32_t p10 = c10;
	std::uint32_t p14 = c14;
	detail::quarter_round(p2, p6, p10, p14);

	std::uint32_t p3 = c3;
	std::uint32_t p7 = c7;
	std::uint32_t p11 = c11;
	std::uint32_t p15 = c15;
	detail::quarter_round(p3, p7, p11, p15);

	while (dst_len >= block_size) {
		std::uint32_t fcr0 = c0;
		std::uint32_t fcr4 = c4;
		std::uint32_t fcr8 = c8;
		std::uint32_t fcr12 = c12;
		detail::quarter_round(fcr0, fcr4, fcr8, fcr12);

		std::uint32_t x0 = fcr0;
		std::uint32_t x5 = p5;
		std::uint32_t x10 = p10;
		std::uint32_t x15 = p15;
		detail::quarter_round(x0, x5, x10, x15);

		std::uint32_t x1 = p1;
		std::uint32_t x6 = p6;
		std::uint32_t x11 = p11;
		std::uint32_t x12 = fcr12;
		detail::quarter_round(x1, x6, x11, x12);

		std::uint32_t x2 = p2;
		std::uint32_t x7 = p7;
		std::uint32_t x8 = fcr8;
		std::uint32_t x13 = p13;
		detail::quarter_round(x2, x7, x8, x13);

		std::uint32_t x3 = p3;
		std::uint32_t x4 = fcr4;
		std::uint32_t x9 = p9;
		std::uint32_t x14 = p14;
		detail::quarter_round(x3, x4, x9, x14);

		for (int round = 0; round < 3; round++) {
			detail::quarter_round(x0, x4, x8, x12);
			detail::quarter_round(x1, x5, x9, x13);
			detail::quarter_round(x2, x6, x10, x14);
			detail::quarter_round(x3, x7, x11, x15);

			detail::quarter_round(x0, x5, x10, x15);
			detail::quarter_round(x1, x6, x11, x12);
			detail::quarter_round(x2, x7, x8, x13);
			detail::quarter_round(x3, x4, x9, x14);
		}

		store32_le(dst + 0, x0 + c0);
		store32_le(dst + 4, x1 + c1);
		store32_le(dst + 8, x2 + c2);
		store32_le(dst + 12, x3 + c3);
		store32_le(dst + 16, x4 + c4);
		store32_le(dst + 20, x5 + c5);
		store32_le(dst + 24, x6 + c6);
		store32_le(dst + 28, x7 + c7);
		store32_le(dst + 32, x8 + c8);
		store32_le(dst + 36, x9 + c9);
		store32_le(dst + 40, x10 + c10);
		store32_le(dst + 44, x11 + c11);
		store32_le(dst + 48, x12 + c12);
		store32_le(dst + 52, x13 + c13);
		store32_le(dst + 56, x14 + c14);
		store32_le(dst + 60, x15 + c15);

		c12++;
		dst += block_size;
		dst_len -= block_size;
	}
}

} // namespace chacha8c

#endif
