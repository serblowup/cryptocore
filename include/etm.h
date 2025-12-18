#ifndef ETM_H
#define ETM_H

#include "main.h"
#include "hmac.h"

typedef struct {
    BYTE enc_key[AES_128_KEY_SIZE];
    BYTE mac_key[HMAC_DIGEST_SIZE];
    cipher_mode_t enc_mode;
} etm_ctx_t;

int etm_init(etm_ctx_t *ctx, cipher_mode_t enc_mode,
             const BYTE *master_key, size_t key_len);

int etm_encrypt(etm_ctx_t *ctx,
               const BYTE *plaintext, size_t plaintext_len,
               const BYTE *aad, size_t aad_len,
               BYTE **output, size_t *output_len);

int etm_decrypt(etm_ctx_t *ctx,
               const BYTE *input, size_t input_len,
               const BYTE *aad, size_t aad_len,
               BYTE **output, size_t *output_len);

void etm_cleanup(etm_ctx_t *ctx);

int encrypt_then_mac(cipher_mode_t enc_mode,
                     const BYTE *key, size_t key_len,
                     const BYTE *plaintext, size_t plaintext_len,
                     const BYTE *aad, size_t aad_len,
                     BYTE **output, size_t *output_len);

int decrypt_then_verify(cipher_mode_t enc_mode,
                        const BYTE *key, size_t key_len,
                        const BYTE *input, size_t input_len,
                        const BYTE *aad, size_t aad_len,
                        BYTE **output, size_t *output_len);

#endif
