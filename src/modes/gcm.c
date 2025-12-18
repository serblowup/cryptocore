/*
 * gcm.c
 *
 *  Created on: 2 дек. 2025 г.
 *      Author: sergey
 */

#include "../../include/gcm.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>

static const BYTE gcm_Rb[16] = {
    0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void gcm_mult_gf(const BYTE *x, const BYTE *y, BYTE *result) {
    BYTE v[16];
    BYTE z[16] = {0};
    int i, j;

    memcpy(v, y, 16);

    for (i = 0; i < 16; i++) {
        BYTE x_byte = x[i];
        for (j = 7; j >= 0; j--) {
            if (x_byte & (1 << j)) {
                for (int k = 0; k < 16; k++) {
                    z[k] ^= v[k];
                }
            }

            int lsb = v[15] & 1;

            for (int k = 15; k > 0; k--) {
                v[k] = (v[k] >> 1) | ((v[k-1] & 1) << 7);
            }
            v[0] >>= 1;

            if (lsb) {
                for (int k = 0; k < 16; k++) {
                    v[k] ^= gcm_Rb[k];
                }
            }
        }
    }

    memcpy(result, z, 16);
}

void gcm_mult_gf_optimized(const BYTE *x, const BYTE *y, BYTE *result,
                          const BYTE (*table)[16]) {
    (void)y;

    BYTE z[16] = {0};

    for (int i = 15; i >= 0; i--) {
        BYTE byte = x[i];

        BYTE low_nibble = byte & 0x0F;
        if (low_nibble != 0) {
            for (int k = 0; k < 16; k++) {
                z[k] ^= table[low_nibble][k];
            }
        }

        BYTE high_nibble = (byte >> 4) & 0x0F;
        if (high_nibble != 0) {
            BYTE temp[16];
            memcpy(temp, table[high_nibble], 16);

            for (int shift = 0; shift < 8; shift++) {
                int lsb = temp[15] & 1;
                for (int k = 15; k > 0; k--) {
                    temp[k] = (temp[k] >> 1) | ((temp[k-1] & 1) << 7);
                }
                temp[0] >>= 1;

                if (lsb) {
                    for (int k = 0; k < 16; k++) {
                        temp[k] ^= gcm_Rb[k];
                    }
                }
            }

            for (int k = 0; k < 16; k++) {
                z[k] ^= temp[k];
            }
        }
    }

    memcpy(result, z, 16);
}

void gcm_ghash(const BYTE *H, const BYTE *X, size_t X_len, BYTE *Y) {
    size_t m = X_len / 16;
    BYTE Yi[16] = {0};

    for (size_t i = 0; i < m; i++) {
        BYTE temp[16];

        for (int j = 0; j < 16; j++) {
            temp[j] = Yi[j] ^ X[i * 16 + j];
        }

        gcm_mult_gf(temp, H, Yi);
    }

    memcpy(Y, Yi, 16);
}

void gcm_ghash_optimized(const BYTE *X, size_t X_len, BYTE *Y,
                        const BYTE (*table)[16]) {
    size_t m = X_len / 16;
    BYTE Yi[16] = {0};

    for (size_t i = 0; i < m; i++) {
        BYTE temp[16];

        for (int j = 0; j < 16; j++) {
            temp[j] = Yi[j] ^ X[i * 16 + j];
        }

        gcm_mult_gf_optimized(temp, table[1], Yi, table);
    }

    memcpy(Y, Yi, 16);
}

void gcm_precompute_table(gcm_ctx_t *ctx) {
    memset(ctx->H_table[0], 0, 16);
    ctx->H_table[0][15] = 1;  // H^0 = 1

    memcpy(ctx->H_table[1], ctx->H, 16);  // H^1 = H

    for (int i = 2; i < GCM_TABLE_SIZE; i++) {
        if (i == 2) {
            gcm_mult_gf(ctx->H, ctx->H, ctx->H_table[2]);  // H^2 = H * H
        } else if (i % 2 == 0) {
            int half = i / 2;
            gcm_mult_gf(ctx->H_table[half], ctx->H_table[half], ctx->H_table[i]);
        } else {
            gcm_mult_gf(ctx->H_table[i-1], ctx->H, ctx->H_table[i]);
        }
    }
}

void gcm_increment_counter(BYTE *counter) {
    for (int i = 15; i >= 12; i--) {
        counter[i]++;
        if (counter[i] != 0) {
            break;
        }
    }
}

static void gcm_form_j0(const BYTE *H, const BYTE *iv, size_t iv_len, BYTE *J0) {
    if (iv_len == 12) {
        memcpy(J0, iv, 12);
        memset(J0 + 12, 0, 4);
        J0[15] = 0x01;
    } else {
        size_t s = 128 * ((iv_len * 8 + 127) / 128) - (iv_len * 8);

        size_t total_len = iv_len + (s/8) + 8;
        BYTE *buffer = malloc(total_len);
        if (!buffer) return;

        size_t offset = 0;
        memcpy(buffer, iv, iv_len);
        offset += iv_len;

        memset(buffer + offset, 0, s/8);
        offset += s/8;

        uint64_t iv_len_bits = (uint64_t)iv_len * 8;
        for (int i = 7; i >= 0; i--) {
            buffer[offset++] = (iv_len_bits >> (i * 8)) & 0xFF;
        }

        BYTE H_table[GCM_TABLE_SIZE][16];
        memset(H_table[0], 0, 16);
        H_table[0][15] = 1;
        memcpy(H_table[1], H, 16);

        for (int i = 2; i < GCM_TABLE_SIZE; i++) {
            if (i == 2) {
                gcm_mult_gf(H, H, H_table[2]);
            } else if (i % 2 == 0) {
                int half = i / 2;
                gcm_mult_gf(H_table[half], H_table[half], H_table[i]);
            } else {
                gcm_mult_gf(H_table[i-1], H, H_table[i]);
            }
        }

        gcm_ghash_optimized(buffer, total_len, J0, H_table);

        free(buffer);
    }
}

void gcm_gctr(const BYTE *key, const BYTE *ICB,
              const BYTE *X, size_t X_len, BYTE *Y) {
    BYTE counter[16];
    size_t n = (X_len + 15) / 16;
    size_t bytes_processed = 0;

    memcpy(counter, ICB, 16);

    for (size_t i = 0; i < n; i++) {
        BYTE *ecb_out = NULL;
        size_t ecb_len;

        if (!ecb_encrypt_no_padding(key, counter, 16, &ecb_out, &ecb_len)) {
            return;
        }

        size_t bytes_to_process = (X_len - bytes_processed < 16) ?
                                   X_len - bytes_processed : 16;

        for (size_t j = 0; j < bytes_to_process; j++) {
            Y[bytes_processed + j] = X[bytes_processed + j] ^ ecb_out[j];
        }

        bytes_processed += bytes_to_process;
        free(ecb_out);

        gcm_increment_counter(counter);
    }
}

int gcm_init(gcm_ctx_t *ctx, const BYTE *key, const BYTE *nonce, size_t nonce_len) {
    if (!ctx || !key) return 0;

    memset(ctx, 0, sizeof(gcm_ctx_t));
    memcpy(ctx->key, key, 16);

    BYTE zero_block[16] = {0};
    BYTE *H_result = NULL;
    size_t H_len;

    if (!ecb_encrypt_no_padding(key, zero_block, 16, &H_result, &H_len)) {
        return 0;
    }
    memcpy(ctx->H, H_result, 16);
    free(H_result);

    gcm_precompute_table(ctx);

    if (nonce) {
        size_t copy_len = (nonce_len < 12) ? nonce_len : 12;
        memcpy(ctx->nonce, nonce, copy_len);
        if (copy_len < 12) {
            memset(ctx->nonce + copy_len, 0, 12 - copy_len);
        }
        ctx->nonce_provided = 1;
    } else {
        if (generate_random_bytes(ctx->nonce, 12) != 1) {
            return 0;
        }
        ctx->nonce_provided = 0;
    }

    gcm_form_j0(ctx->H, ctx->nonce, 12, ctx->J0);

    return 1;
}

void gcm_cleanup(gcm_ctx_t *ctx) {
    if (ctx) {
        memset(ctx->key, 0, 16);
        memset(ctx->H, 0, 16);
        memset(ctx->H_table, 0, sizeof(ctx->H_table));
        memset(ctx->J0, 0, 16);
        memset(ctx->nonce, 0, 12);
    }
}

int gcm_encrypt_ctx(gcm_ctx_t *ctx,
                    const BYTE *plaintext, size_t plaintext_len,
                    const BYTE *aad, size_t aad_len,
                    BYTE *ciphertext, BYTE *tag) {
    if (!ctx || !plaintext || !ciphertext || !tag) {
        return GCM_ERROR;
    }

    BYTE inc_J0[16];
    memcpy(inc_J0, ctx->J0, 16);
    gcm_increment_counter(inc_J0);

    gcm_gctr(ctx->key, inc_J0, plaintext, plaintext_len, ciphertext);

    size_t u = (16 - (plaintext_len % 16)) % 16;
    size_t v = (16 - (aad_len % 16)) % 16;

    size_t total_len = aad_len + v + plaintext_len + u + 8 + 8;
    BYTE *ghash_input = malloc(total_len);
    if (!ghash_input) return GCM_ERROR;

    size_t offset = 0;

    if (aad_len > 0) {
        memcpy(ghash_input, aad, aad_len);
        offset += aad_len;
    }

    if (v > 0) {
        memset(ghash_input + offset, 0, v);
        offset += v;
    }

    memcpy(ghash_input + offset, ciphertext, plaintext_len);
    offset += plaintext_len;

    if (u > 0) {
        memset(ghash_input + offset, 0, u);
        offset += u;
    }

    uint64_t aad_len_bits = (uint64_t)aad_len * 8;
    for (int i = 7; i >= 0; i--) {
        ghash_input[offset++] = (aad_len_bits >> (i * 8)) & 0xFF;
    }

    uint64_t ciphertext_len_bits = (uint64_t)plaintext_len * 8;
    for (int i = 7; i >= 0; i--) {
        ghash_input[offset++] = (ciphertext_len_bits >> (i * 8)) & 0xFF;
    }

    BYTE S[16];
    gcm_ghash_optimized(ghash_input, total_len, S, ctx->H_table);

    BYTE encrypted_S[16];
    gcm_gctr(ctx->key, ctx->J0, S, 16, encrypted_S);

    memcpy(tag, encrypted_S, 16);

    free(ghash_input);
    return GCM_SUCCESS;
}

int gcm_decrypt_ctx(gcm_ctx_t *ctx,
                    const BYTE *ciphertext, size_t ciphertext_len,
                    const BYTE *aad, size_t aad_len,
                    const BYTE *tag,
                    BYTE *plaintext) {
    if (!ctx || !ciphertext || !tag || !plaintext) {
        return GCM_ERROR;
    }

    size_t u = (16 - (ciphertext_len % 16)) % 16;
    size_t v = (16 - (aad_len % 16)) % 16;

    size_t total_len = aad_len + v + ciphertext_len + u + 8 + 8;
    BYTE *ghash_input = malloc(total_len);
    if (!ghash_input) return GCM_ERROR;

    size_t offset = 0;

    if (aad_len > 0) {
        memcpy(ghash_input, aad, aad_len);
        offset += aad_len;
    }

    if (v > 0) {
        memset(ghash_input + offset, 0, v);
        offset += v;
    }

    memcpy(ghash_input + offset, ciphertext, ciphertext_len);
    offset += ciphertext_len;

    if (u > 0) {
        memset(ghash_input + offset, 0, u);
        offset += u;
    }

    uint64_t aad_len_bits = (uint64_t)aad_len * 8;
    for (int i = 7; i >= 0; i--) {
        ghash_input[offset++] = (aad_len_bits >> (i * 8)) & 0xFF;
    }

    uint64_t ciphertext_len_bits = (uint64_t)ciphertext_len * 8;
    for (int i = 7; i >= 0; i--) {
        ghash_input[offset++] = (ciphertext_len_bits >> (i * 8)) & 0xFF;
    }

    BYTE S[16];
    gcm_ghash_optimized(ghash_input, total_len, S, ctx->H_table);

    BYTE computed_tag[16];
    gcm_gctr(ctx->key, ctx->J0, S, 16, computed_tag);

    int tag_valid = 1;
    for (int i = 0; i < 16; i++) {
        tag_valid &= (computed_tag[i] == tag[i]);
    }

    free(ghash_input);

    if (!tag_valid) {
        return GCM_AUTH_FAILED;
    }

    BYTE inc_J0[16];
    memcpy(inc_J0, ctx->J0, 16);
    gcm_increment_counter(inc_J0);

    gcm_gctr(ctx->key, inc_J0, ciphertext, ciphertext_len, plaintext);

    return GCM_SUCCESS;
}

int gcm_encrypt_full(const BYTE *key,
                     const BYTE *plaintext, size_t plaintext_len,
                     const BYTE *aad, size_t aad_len,
                     BYTE **output, size_t *output_len) {
    gcm_ctx_t ctx;
    BYTE nonce[12];
    BYTE *ciphertext = NULL;
    BYTE tag[16];

    if (generate_random_bytes(nonce, 12) != 1) {
        return 0;
    }

    if (!gcm_init(&ctx, key, nonce, 12)) {
        return 0;
    }

    ciphertext = malloc(plaintext_len);
    if (!ciphertext) {
        gcm_cleanup(&ctx);
        return 0;
    }

    if (gcm_encrypt_ctx(&ctx, plaintext, plaintext_len, aad, aad_len, ciphertext, tag) != GCM_SUCCESS) {
        free(ciphertext);
        gcm_cleanup(&ctx);
        return 0;
    }

    *output_len = 12 + plaintext_len + 16;
    *output = malloc(*output_len);
    if (!*output) {
        free(ciphertext);
        gcm_cleanup(&ctx);
        return 0;
    }

    memcpy(*output, nonce, 12);
    memcpy(*output + 12, ciphertext, plaintext_len);
    memcpy(*output + 12 + plaintext_len, tag, 16);

    free(ciphertext);
    gcm_cleanup(&ctx);
    return 1;
}

int gcm_decrypt_full(const BYTE *key,
                     const BYTE *input, size_t input_len,
                     const BYTE *aad, size_t aad_len,
                     BYTE **output, size_t *output_len) {
    if (input_len < 12 + 16) {
        fprintf(stderr, "Error: Input too short for GCM (needs at least 28 bytes)\n");
        return 0;
    }

    gcm_ctx_t ctx;
    const BYTE *nonce = input;
    size_t ciphertext_len = input_len - 12 - 16;
    const BYTE *ciphertext = input + 12;
    const BYTE *tag = input + 12 + ciphertext_len;

    if (!gcm_init(&ctx, key, nonce, 12)) {
        fprintf(stderr, "Error: GCM init failed\n");
        return 0;
    }

    *output = malloc(ciphertext_len);
    if (!*output) {
        gcm_cleanup(&ctx);
        fprintf(stderr, "Error: Memory allocation failed\n");
        return 0;
    }

    int result = gcm_decrypt_ctx(&ctx, ciphertext, ciphertext_len, aad, aad_len, tag, *output);

    if (result == GCM_SUCCESS) {
        *output_len = ciphertext_len;
    } else {
        if (result == GCM_AUTH_FAILED) {
            fprintf(stderr, "Error: GCM authentication failed\n");
        } else {
            fprintf(stderr, "Error: GCM decryption failed\n");
        }
        memset(*output, 0, ciphertext_len);
        free(*output);
        *output = NULL;
        *output_len = 0;
    }

    gcm_cleanup(&ctx);
    return (result == GCM_SUCCESS);
}

int gcm_encrypt_with_fixed_nonce(const BYTE *key,
                                 const BYTE *nonce, size_t nonce_len,
                                 const BYTE *plaintext, size_t plaintext_len,
                                 const BYTE *aad, size_t aad_len,
                                 BYTE *ciphertext, BYTE *tag) {
    gcm_ctx_t ctx;

    if (!gcm_init(&ctx, key, nonce, nonce_len)) {
        return 0;
    }

    int result = gcm_encrypt_ctx(&ctx, plaintext, plaintext_len, aad, aad_len, ciphertext, tag);

    gcm_cleanup(&ctx);
    return (result == GCM_SUCCESS);
}

int gcm_decrypt_with_fixed_nonce(const BYTE *key,
                                 const BYTE *nonce, size_t nonce_len,
                                 const BYTE *ciphertext, size_t ciphertext_len,
                                 const BYTE *aad, size_t aad_len,
                                 const BYTE *tag,
                                 BYTE *plaintext) {
    gcm_ctx_t ctx;

    if (!gcm_init(&ctx, key, nonce, nonce_len)) {
        return 0;
    }

    int result = gcm_decrypt_ctx(&ctx, ciphertext, ciphertext_len, aad, aad_len, tag, plaintext);

    gcm_cleanup(&ctx);
    return (result == GCM_SUCCESS);
}
