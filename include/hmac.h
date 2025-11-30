/*
 * hmac.h
 *
 *  Created on: 29 нояб. 2025 г.
 *      Author: sergey
 */

#ifndef INCLUDE_HMAC_H_
#define INCLUDE_HMAC_H_

#include "sha256.h"
#include <stddef.h>

#define HMAC_BLOCK_SIZE 64
#define HMAC_DIGEST_SIZE 32

typedef struct {
    sha256_ctx_t hash_ctx;
    BYTE key[HMAC_BLOCK_SIZE];
    BYTE o_key_pad[HMAC_BLOCK_SIZE];
    BYTE i_key_pad[HMAC_BLOCK_SIZE];
} hmac_ctx_t;

void hmac_init(hmac_ctx_t *ctx, const BYTE *key, size_t key_len);
void hmac_update(hmac_ctx_t *ctx, const BYTE *data, size_t data_len);
void hmac_final(hmac_ctx_t *ctx, BYTE *digest);
void hmac_compute(const BYTE *key, size_t key_len, const BYTE *data, size_t data_len, BYTE *digest);
int hmac_verify(const BYTE *key, size_t key_len, const BYTE *data, size_t data_len, const BYTE *expected_digest);
int hmac_file_compute(const BYTE *key, size_t key_len, const char *filename, BYTE *digest, size_t chunk_size);

#endif /* INCLUDE_HMAC_H_ */
