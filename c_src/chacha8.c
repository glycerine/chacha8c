// Copyright 2026 Jason E. Aten, Ph.D. All rights reserved.
// Copyright 2023 The Go Authors. All rights reserved.
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

#include "chacha8.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// note: we only did a little-endian port. So this is trying to prevent
// problems by barfing on big-endian machines rather than mis-handling them.

#ifndef CHACHA8_NO_MAIN
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && defined(__ORDER_LITTLE_ENDIAN__)
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#error "chacha8 main refuses to compile on big-endian machines"
#elif __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "chacha8 main could not confirm a little-endian machine"
#endif
#elif defined(_WIN32)
/* Supported Windows targets are little-endian. */
#else
#error "chacha8 main could not determine machine endianness"
#endif
#endif

// Q: what are these CHACHA8_J0, CHACHA8_J1, CHACHA8_J2, CHACHA8_J3 constants?
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

static uint64_t load64_le(const uint8_t *p)
{
	return ((uint64_t)load32_le(p)) | ((uint64_t)load32_le(p + 4) << 32);
}

static void store64_le(uint8_t *p, uint64_t x)
{
	store32_le(p, (uint32_t)x);
	store32_le(p + 4, (uint32_t)(x >> 32));
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


enum {
	CHACHA8_CTR_INC = 4,
	CHACHA8_CTR_MAX = 16,
	CHACHA8_CHUNK = 32,
	CHACHA8_RESEED = 4,
};

struct chacha8rand_state {
	uint64_t buf[CHACHA8_CHUNK];
	uint64_t seed[4];
	uint32_t i;
	uint32_t n;
	uint32_t c;
};

struct ChaCha8 {
	struct chacha8rand_state state;
	uint8_t read_buf[8];
	size_t read_len;
};

static void chacha8rand_setup(const uint64_t seed[4], uint32_t b[16][4], uint32_t counter)
{
	size_t lane;

	for (lane = 0; lane < 4; lane++) {
		b[0][lane] = CHACHA8_J0;
		b[1][lane] = CHACHA8_J1;
		b[2][lane] = CHACHA8_J2;
		b[3][lane] = CHACHA8_J3;
		b[4][lane] = (uint32_t)seed[0];
		b[5][lane] = (uint32_t)(seed[0] >> 32);
		b[6][lane] = (uint32_t)seed[1];
		b[7][lane] = (uint32_t)(seed[1] >> 32);
		b[8][lane] = (uint32_t)seed[2];
		b[9][lane] = (uint32_t)(seed[2] >> 32);
		b[10][lane] = (uint32_t)seed[3];
		b[11][lane] = (uint32_t)(seed[3] >> 32);
		b[12][lane] = counter + (uint32_t)lane;
		b[13][lane] = 0;
		b[14][lane] = 0;
		b[15][lane] = 0;
	}
}

static void chacha8rand_block(const uint64_t seed[4], uint64_t buf[CHACHA8_CHUNK], uint32_t counter)
{
	uint32_t b[16][4];
	size_t lane;
	size_t word;

	chacha8rand_setup(seed, b, counter);

	for (lane = 0; lane < 4; lane++) {
		uint32_t b0 = b[0][lane];
		uint32_t b1 = b[1][lane];
		uint32_t b2 = b[2][lane];
		uint32_t b3 = b[3][lane];
		uint32_t b4 = b[4][lane];
		uint32_t b5 = b[5][lane];
		uint32_t b6 = b[6][lane];
		uint32_t b7 = b[7][lane];
		uint32_t b8 = b[8][lane];
		uint32_t b9 = b[9][lane];
		uint32_t b10 = b[10][lane];
		uint32_t b11 = b[11][lane];
		uint32_t b12 = b[12][lane];
		uint32_t b13 = b[13][lane];
		uint32_t b14 = b[14][lane];
		uint32_t b15 = b[15][lane];
		int round;

		for (round = 0; round < 4; round++) {
			quarter_round(&b0, &b4, &b8, &b12);
			quarter_round(&b1, &b5, &b9, &b13);
			quarter_round(&b2, &b6, &b10, &b14);
			quarter_round(&b3, &b7, &b11, &b15);

			quarter_round(&b0, &b5, &b10, &b15);
			quarter_round(&b1, &b6, &b11, &b12);
			quarter_round(&b2, &b7, &b8, &b13);
			quarter_round(&b3, &b4, &b9, &b14);
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

	for (word = 0; word < 16; word++) {
		buf[word * 2 + 0] = (uint64_t)b[word][0] | ((uint64_t)b[word][1] << 32);
		buf[word * 2 + 1] = (uint64_t)b[word][2] | ((uint64_t)b[word][3] << 32);
	}
}

static void chacha8rand_state_init(struct chacha8rand_state *s, const uint8_t seed[CHACHA8_KEY_SIZE])
{
	s->seed[0] = load64_le(seed + 0 * 8);
	s->seed[1] = load64_le(seed + 1 * 8);
	s->seed[2] = load64_le(seed + 2 * 8);
	s->seed[3] = load64_le(seed + 3 * 8);
	chacha8rand_block(s->seed, s->buf, 0);
	s->c = 0;
	s->i = 0;
	s->n = CHACHA8_CHUNK;
}

static int chacha8rand_state_next(struct chacha8rand_state *s, uint64_t *out)
{
	uint32_t i = s->i;

	if (i >= s->n) {
		return 0;
	}
	s->i = i + 1;
	*out = s->buf[i & 31u];
	return 1;
}

static void chacha8rand_state_refill(struct chacha8rand_state *s)
{
	s->c += CHACHA8_CTR_INC;
	if (s->c == CHACHA8_CTR_MAX) {
		s->seed[0] = s->buf[CHACHA8_CHUNK - CHACHA8_RESEED + 0];
		s->seed[1] = s->buf[CHACHA8_CHUNK - CHACHA8_RESEED + 1];
		s->seed[2] = s->buf[CHACHA8_CHUNK - CHACHA8_RESEED + 2];
		s->seed[3] = s->buf[CHACHA8_CHUNK - CHACHA8_RESEED + 3];
		s->c = 0;
	}
	chacha8rand_block(s->seed, s->buf, s->c);
	s->i = 0;
	s->n = CHACHA8_CHUNK;
	if (s->c == CHACHA8_CTR_MAX - CHACHA8_CTR_INC) {
		s->n = CHACHA8_CHUNK - CHACHA8_RESEED;
	}
}

ChaCha8 *NewChaCha8(const uint8_t seed[CHACHA8_KEY_SIZE])
{
	ChaCha8 *c = (ChaCha8 *)malloc(sizeof(*c));

	if (c == NULL) {
		return NULL;
	}
	chacha8rand_state_init(&c->state, seed);
	memset(c->read_buf, 0, sizeof(c->read_buf));
	c->read_len = 0;
	return c;
}

void ChaCha8_Free(ChaCha8 *c)
{
	if (c != NULL) {
		memset(c, 0, sizeof(*c));
		free(c);
	}
}

uint64_t ChaCha8_Uint64(ChaCha8 *c)
{
	uint64_t x;

	for (;;) {
		if (chacha8rand_state_next(&c->state, &x)) {
			return x;
		}
		chacha8rand_state_refill(&c->state);
	}
}

// ChaCha8_Rand emulates C rand() from <random> in returning a non-negative
// integer in the range of [0, 2147483647] inclusive. In other
// words we assume a RAND_MAX of 2147483647. For this
// value of RAND_MAX our implementation is fast and has no modulo bias.
int ChaCha8_Rand(ChaCha8 *c)
{
        return (int)(ChaCha8_Uint64(c) >> 33);
}


size_t ChaCha8_Read(ChaCha8 *c, uint8_t *p, size_t len)
{
	size_t n = 0;

	if (c->read_len > 0) {
		size_t take = len < c->read_len ? len : c->read_len;

		memcpy(p, c->read_buf + sizeof(c->read_buf) - c->read_len, take);
		c->read_len -= take;
		p += take;
		len -= take;
		n += take;
	}

	while (len >= 8) {
		store64_le(p, ChaCha8_Uint64(c));
		p += 8;
		len -= 8;
		n += 8;
	}

	if (len > 0) {
		store64_le(c->read_buf, ChaCha8_Uint64(c));
		memcpy(p, c->read_buf, len);
		c->read_len = 8 - len;
		n += len;
	}

	return n;
}

#ifndef CHACHA8_NO_MAIN
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
	uint8_t seed[CHACHA8_KEY_SIZE];
	ChaCha8 *rng;
	uint64_t uints[3 * ((1024 - 32) / 8)];
	size_t uints_len = 0;
	int pass;

	memcpy(seed, "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", CHACHA8_KEY_SIZE);
	rng = NewChaCha8(seed);
	if (rng == NULL) {
		return 1;
	}

	for (pass = 0; pass < 3; pass++) {
		uint8_t output[1024 - CHACHA8_KEY_SIZE];
		size_t output_len = sizeof(output);
		size_t i;

		ChaCha8_Read(rng, output, output_len);
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

	ChaCha8_Free(rng);
	return 0;
}
#endif
