/*
 * sha256.h
 *
 *  Created on: 27 нояб. 2025 г.
 *      Author: sergey
 */

#ifndef INCLUDE_SHA256_H_
#define INCLUDE_SHA256_H_

#include <stdint.h>
#include <stddef.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef unsigned char BYTE;

typedef struct {
    uint32_t state[8];
    uint64_t count;
    BYTE buffer[SHA256_BLOCK_SIZE];
} sha256_ctx_t;

void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const BYTE *data, size_t len);
void sha256_final(sha256_ctx_t *ctx, BYTE *digest);
void sha256_hash(const BYTE *data, size_t len, BYTE *digest);
int sha256_file_hash(const char *filename, BYTE *digest, size_t chunk_size);

#endif /* INCLUDE_SHA256_H_ */
