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

#include "chacha8.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

enum {
	CHACHA8_J0 = 0x61707865u,
	CHACHA8_J1 = 0x3320646eu,
	CHACHA8_J2 = 0x79622d32u,
	CHACHA8_J3 = 0x6b206574u,
};

static uint32_t load32_le(const uint8_t *p)
{
	return ((uint32_t)p[0]) |
	       ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t x)
{
	p[0] = (uint8_t)x;
	p[1] = (uint8_t)(x >> 8);
	p[2] = (uint8_t)(x >> 16);
	p[3] = (uint8_t)(x >> 24);
}

static uint32_t rotl32(uint32_t x, unsigned int n)
{
	return (x << n) | (x >> (32 - n));
}

static void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
	*a += *b;
	*d ^= *a;
	*d = rotl32(*d, 16);
	*c += *d;
	*b ^= *c;
	*b = rotl32(*b, 12);
	*a += *b;
	*d ^= *a;
	*d = rotl32(*d, 8);
	*c += *d;
	*b ^= *c;
	*b = rotl32(*b, 7);
}

void chacha8(const uint8_t key[CHACHA8_KEY_SIZE], uint8_t *dst, size_t dst_len)
{
	uint32_t k[8];
	uint32_t c0 = CHACHA8_J0;
	uint32_t c1 = CHACHA8_J1;
	uint32_t c2 = CHACHA8_J2;
	uint32_t c3 = CHACHA8_J3;
	uint32_t c4;
	uint32_t c5;
	uint32_t c6;
	uint32_t c7;
	uint32_t c8;
	uint32_t c9;
	uint32_t c10;
	uint32_t c11;
	uint32_t c12 = 0;
	uint32_t c13 = 0;
	uint32_t c14 = 0;
	uint32_t c15 = 0;
	uint32_t p1;
	uint32_t p5;
	uint32_t p9;
	uint32_t p13;
	uint32_t p2;
	uint32_t p6;
	uint32_t p10;
	uint32_t p14;
	uint32_t p3;
	uint32_t p7;
	uint32_t p11;
	uint32_t p15;
	size_t i;

	for (i = 0; i < 8; i++) {
		k[i] = load32_le(key + i * 4);
	}

	c4 = k[0];
	c5 = k[1];
	c6 = k[2];
	c7 = k[3];
	c8 = k[4];
	c9 = k[5];
	c10 = k[6];
	c11 = k[7];

	p1 = c1;
	p5 = c5;
	p9 = c9;
	p13 = c13;
	quarter_round(&p1, &p5, &p9, &p13);

	p2 = c2;
	p6 = c6;
	p10 = c10;
	p14 = c14;
	quarter_round(&p2, &p6, &p10, &p14);

	p3 = c3;
	p7 = c7;
	p11 = c11;
	p15 = c15;
	quarter_round(&p3, &p7, &p11, &p15);

	while (dst_len >= CHACHA8_BLOCK_SIZE) {
		uint32_t fcr0 = c0;
		uint32_t fcr4 = c4;
		uint32_t fcr8 = c8;
		uint32_t fcr12 = c12;
		uint32_t x0;
		uint32_t x1;
		uint32_t x2;
		uint32_t x3;
		uint32_t x4;
		uint32_t x5;
		uint32_t x6;
		uint32_t x7;
		uint32_t x8;
		uint32_t x9;
		uint32_t x10;
		uint32_t x11;
		uint32_t x12;
		uint32_t x13;
		uint32_t x14;
		uint32_t x15;
		int round;

		quarter_round(&fcr0, &fcr4, &fcr8, &fcr12);

		x0 = fcr0;
		x5 = p5;
		x10 = p10;
		x15 = p15;
		quarter_round(&x0, &x5, &x10, &x15);

		x1 = p1;
		x6 = p6;
		x11 = p11;
		x12 = fcr12;
		quarter_round(&x1, &x6, &x11, &x12);

		x2 = p2;
		x7 = p7;
		x8 = fcr8;
		x13 = p13;
		quarter_round(&x2, &x7, &x8, &x13);

		x3 = p3;
		x4 = fcr4;
		x9 = p9;
		x14 = p14;
		quarter_round(&x3, &x4, &x9, &x14);

		for (round = 0; round < 3; round++) {
			quarter_round(&x0, &x4, &x8, &x12);
			quarter_round(&x1, &x5, &x9, &x13);
			quarter_round(&x2, &x6, &x10, &x14);
			quarter_round(&x3, &x7, &x11, &x15);

			quarter_round(&x0, &x5, &x10, &x15);
			quarter_round(&x1, &x6, &x11, &x12);
			quarter_round(&x2, &x7, &x8, &x13);
			quarter_round(&x3, &x4, &x9, &x14);
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
		dst += CHACHA8_BLOCK_SIZE;
		dst_len -= CHACHA8_BLOCK_SIZE;
	}
}

#ifndef CHACHA8_NO_MAIN
static uint64_t load64_le(const uint8_t *p)
{
	return ((uint64_t)load32_le(p)) | ((uint64_t)load32_le(p + 4) << 32);
}

static void print_hex_line(const uint8_t *p, size_t n)
{
	static const char hex[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < n; i++) {
		putchar(hex[p[i] >> 4]);
		putchar(hex[p[i] & 0x0f]);
	}
	putchar('\n');
}

int main(void)
{
	uint8_t input[CHACHA8_KEY_SIZE];
	uint64_t uints[3 * ((1024 - 32) / 8)];
	size_t uints_len = 0;
	int pass;

	memcpy(input, "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", CHACHA8_KEY_SIZE);

	for (pass = 0; pass < 3; pass++) {
		uint8_t stream[1024];
		uint8_t output[1024];
		uint8_t *streamp;
		size_t output_len = 0;
		size_t i;
		uint32_t block;

		chacha8(input, stream, sizeof(stream));

		for (block = 0; block < 16; block++) {
			uint8_t *b = stream + block * CHACHA8_BLOCK_SIZE;

			store32_le(b + 0 * 4, load32_le(b + 0 * 4) - CHACHA8_J0);
			store32_le(b + 1 * 4, load32_le(b + 1 * 4) - CHACHA8_J1);
			store32_le(b + 2 * 4, load32_le(b + 2 * 4) - CHACHA8_J2);
			store32_le(b + 3 * 4, load32_le(b + 3 * 4) - CHACHA8_J3);
			store32_le(b + 12 * 4, load32_le(b + 12 * 4) - block);
		}

		streamp = stream;
		for (i = 0; i < 16; i += 4) {
			size_t word;

			for (word = 0; word < CHACHA8_BLOCK_SIZE; word += 4) {
				memcpy(output + output_len, streamp + 0 * CHACHA8_BLOCK_SIZE + word, 4);
				output_len += 4;
				memcpy(output + output_len, streamp + 1 * CHACHA8_BLOCK_SIZE + word, 4);
				output_len += 4;
				memcpy(output + output_len, streamp + 2 * CHACHA8_BLOCK_SIZE + word, 4);
				output_len += 4;
				memcpy(output + output_len, streamp + 3 * CHACHA8_BLOCK_SIZE + word, 4);
				output_len += 4;
			}
			streamp += 4 * CHACHA8_BLOCK_SIZE;
		}

		memcpy(input, output + 1024 - CHACHA8_KEY_SIZE, CHACHA8_KEY_SIZE);
		output_len = 1024 - CHACHA8_KEY_SIZE;

		for (i = 0; i < output_len; i += 8) {
			uints[uints_len++] = load64_le(output + i);
		}

		for (i = 0; i < output_len; i += 32) {
			print_hex_line(output + i, 32);
		}
	}

	for (size_t i = 0; i < uints_len; i++) {
		if (i % 4 == 0) {
			printf("\n");
		}
		printf("0x%016" PRIx64 ", ", uints[i]);
	}

	return 0;
}
#endif
