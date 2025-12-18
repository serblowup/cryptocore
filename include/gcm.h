/*
 * gcm.h
 *
 *  Created on: 2 дек. 2025 г.
 *      Author: sergey
 */

#ifndef MODES_GCM_H
#define MODES_GCM_H

#include "main.h"

#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE 16
#define GCM_BLOCK_SIZE 16
#define GCM_TABLE_SIZE 16

#define GCM_SUCCESS 1
#define GCM_AUTH_FAILED 0
#define GCM_ERROR -1

#define GCM_MAX_IV_SIZE 1024
#define GCM_MAX_PT_SIZE (1 << 24)

typedef struct {
    BYTE key[16];
    BYTE H[16];
    BYTE H_table[GCM_TABLE_SIZE][16];
    BYTE J0[16];
    BYTE nonce[12];
    int nonce_provided;
} gcm_ctx_t;

int gcm_init(gcm_ctx_t *ctx, const BYTE *key, const BYTE *nonce, size_t nonce_len);
void gcm_cleanup(gcm_ctx_t *ctx);

int gcm_encrypt_ctx(gcm_ctx_t *ctx,
                    const BYTE *plaintext, size_t plaintext_len,
                    const BYTE *aad, size_t aad_len,
                    BYTE *ciphertext, BYTE *tag);

int gcm_decrypt_ctx(gcm_ctx_t *ctx,
                    const BYTE *ciphertext, size_t ciphertext_len,
                    const BYTE *aad, size_t aad_len,
                    const BYTE *tag,
                    BYTE *plaintext);

int gcm_encrypt_full(const BYTE *key,
                     const BYTE *plaintext, size_t plaintext_len,
                     const BYTE *aad, size_t aad_len,
                     BYTE **output, size_t *output_len);

int gcm_decrypt_full(const BYTE *key,
                     const BYTE *input, size_t input_len,
                     const BYTE *aad, size_t aad_len,
                     BYTE **output, size_t *output_len);

void gcm_mult_gf(const BYTE *x, const BYTE *y, BYTE *result);
void gcm_mult_gf_optimized(const BYTE *x, const BYTE *y, BYTE *result,
                          const BYTE (*table)[16]);
void gcm_ghash(const BYTE *H, const BYTE *X, size_t X_len, BYTE *Y);
void gcm_ghash_optimized(const BYTE *X, size_t X_len, BYTE *Y,
                        const BYTE (*table)[16]);
void gcm_gctr(const BYTE *key, const BYTE *ICB,
              const BYTE *X, size_t X_len, BYTE *Y);
void gcm_increment_counter(BYTE *counter);

void gcm_precompute_table(gcm_ctx_t *ctx);

int gcm_encrypt_with_fixed_nonce(const BYTE *key,
                                 const BYTE *nonce, size_t nonce_len,
                                 const BYTE *plaintext, size_t plaintext_len,
                                 const BYTE *aad, size_t aad_len,
                                 BYTE *ciphertext, BYTE *tag);

int gcm_decrypt_with_fixed_nonce(const BYTE *key,
                                 const BYTE *nonce, size_t nonce_len,
                                 const BYTE *ciphertext, size_t ciphertext_len,
                                 const BYTE *aad, size_t aad_len,
                                 const BYTE *tag,
                                 BYTE *plaintext);

#endif /* MODES_GCM_H */
