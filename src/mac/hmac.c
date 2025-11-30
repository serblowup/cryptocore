/*
 * hmac.c
 *
 *  Created on: 29 нояб. 2025 г.
 *      Author: sergey
 */

#include "../include/hmac.h"
#include "../include/main.h"
#include <string.h>
#include <stdio.h>

void hmac_init(hmac_ctx_t *ctx, const BYTE *key, size_t key_len) {
    BYTE processed_key[HMAC_BLOCK_SIZE];

    if (key_len > HMAC_BLOCK_SIZE) {
        sha256_hash(key, key_len, processed_key);
        key_len = HMAC_DIGEST_SIZE;
    } else {
        memcpy(processed_key, key, key_len);
    }

    if (key_len < HMAC_BLOCK_SIZE) {
        memset(processed_key + key_len, 0, HMAC_BLOCK_SIZE - key_len);
    }

    memcpy(ctx->key, processed_key, HMAC_BLOCK_SIZE);

    for (int i = 0; i < HMAC_BLOCK_SIZE; i++) {
        ctx->i_key_pad[i] = processed_key[i] ^ 0x36;
        ctx->o_key_pad[i] = processed_key[i] ^ 0x5C;
    }

    sha256_init(&ctx->hash_ctx);
    sha256_update(&ctx->hash_ctx, ctx->i_key_pad, HMAC_BLOCK_SIZE);
}

void hmac_update(hmac_ctx_t *ctx, const BYTE *data, size_t data_len) {
    sha256_update(&ctx->hash_ctx, data, data_len);
}

void hmac_final(hmac_ctx_t *ctx, BYTE *digest) {
    BYTE inner_hash[HMAC_DIGEST_SIZE];

    sha256_final(&ctx->hash_ctx, inner_hash);

    sha256_ctx_t outer_ctx;
    sha256_init(&outer_ctx);
    sha256_update(&outer_ctx, ctx->o_key_pad, HMAC_BLOCK_SIZE);
    sha256_update(&outer_ctx, inner_hash, HMAC_DIGEST_SIZE);
    sha256_final(&outer_ctx, digest);
}

void hmac_compute(const BYTE *key, size_t key_len, const BYTE *data, size_t data_len, BYTE *digest) {
    hmac_ctx_t ctx;
    hmac_init(&ctx, key, key_len);
    hmac_update(&ctx, data, data_len);
    hmac_final(&ctx, digest);
}

int hmac_verify(const BYTE *key, size_t key_len, const BYTE *data, size_t data_len, const BYTE *expected_digest) {
    BYTE computed_digest[HMAC_DIGEST_SIZE];
    hmac_compute(key, key_len, data, data_len, computed_digest);
    return memcmp(computed_digest, expected_digest, HMAC_DIGEST_SIZE) == 0;
}

int hmac_file_compute(const BYTE *key, size_t key_len, const char *filename, BYTE *digest, size_t chunk_size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file '%s'\n", filename);
        return 0;
    }

    hmac_ctx_t ctx;
    hmac_init(&ctx, key, key_len);

    BYTE *chunk = malloc(chunk_size);
    if (!chunk) {
        fclose(file);
        return 0;
    }

    size_t bytes_read;
    size_t total_bytes = 0;

    while ((bytes_read = fread(chunk, 1, chunk_size, file)) > 0) {
        hmac_update(&ctx, chunk, bytes_read);
        total_bytes += bytes_read;
    }

    hmac_final(&ctx, digest);

    free(chunk);
    fclose(file);

    printf("HMAC computed for %zu bytes from '%s'\n", total_bytes, filename);
    return 1;
}
