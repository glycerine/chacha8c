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

#ifdef __cplusplus
}
#endif

#endif
