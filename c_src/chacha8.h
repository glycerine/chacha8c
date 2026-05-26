#ifndef CHACHA8_H
#define CHACHA8_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CHACHA8_KEY_SIZE 32
#define CHACHA8_BLOCK_SIZE 64

typedef struct ChaCha8 ChaCha8;

ChaCha8 *NewChaCha8(const uint8_t seed[CHACHA8_KEY_SIZE]);
void ChaCha8_Free(ChaCha8 *c);
size_t ChaCha8_Read(ChaCha8 *c, uint8_t *p, size_t len);
uint64_t ChaCha8_Uint64(ChaCha8 *c);

// ChaCha8_Rand emulates C rand() from <random> in returning a non-negative
// integer in the range of [0, 2147483647] inclusive. In other
// words we assume a RAND_MAX of 2147483647. For this
// value of RAND_MAX our implementation is fast and has no modulo bias.
int ChaCha8_Rand(ChaCha8 *c);

// ChaCha8_UnbiasedChoice avoids modulo bias when choosing a non-negative
// integer from among nChoices. If nChoices <= 1, it returns 0.
int64_t ChaCha8_UnbiasedChoice(ChaCha8 *c, int64_t nChoices);

#ifdef __cplusplus
}
#endif

#endif
