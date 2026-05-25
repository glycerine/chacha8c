#ifndef CHACHA8_H
#define CHACHA8_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CHACHA8_KEY_SIZE 32
#define CHACHA8_BLOCK_SIZE 64

void chacha8(const uint8_t key[CHACHA8_KEY_SIZE], uint8_t *dst, size_t dst_len);

#ifdef __cplusplus
}
#endif

#endif
