#include "../../include/etm.h"
#include "../../include/main.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static void derive_keys(const BYTE *master_key, size_t key_len,
                       BYTE *enc_key, BYTE *mac_key) {
    BYTE enc_label[] = "enc";
    BYTE mac_label[] = "mac";

    BYTE enc_hash[HMAC_DIGEST_SIZE];
    hmac_compute(master_key, key_len,
                enc_label, sizeof(enc_label) - 1,
                enc_hash);

    BYTE mac_hash[HMAC_DIGEST_SIZE];
    hmac_compute(master_key, key_len,
                mac_label, sizeof(mac_label) - 1,
                mac_hash);

    memcpy(enc_key, enc_hash, AES_128_KEY_SIZE);
    memcpy(mac_key, mac_hash, HMAC_DIGEST_SIZE);
}

int etm_init(etm_ctx_t *ctx, cipher_mode_t enc_mode,
             const BYTE *master_key, size_t key_len) {
    if (!ctx || !master_key) return 0;

    memset(ctx, 0, sizeof(etm_ctx_t));
    ctx->enc_mode = enc_mode;

    derive_keys(master_key, key_len, ctx->enc_key, ctx->mac_key);

    return 1;
}

int etm_encrypt(etm_ctx_t *ctx,
               const BYTE *plaintext, size_t plaintext_len,
               const BYTE *aad, size_t aad_len,
               BYTE **output, size_t *output_len) {
    if (!ctx || !plaintext || !output || !output_len) return 0;

    BYTE *ciphertext = NULL;
    size_t ciphertext_len = 0;
    BYTE iv[IV_SIZE];

    if (generate_random_bytes(iv, IV_SIZE) != 1) {
        return 0;
    }

    switch(ctx->enc_mode) {
        case MODE_CBC:
            if (!cbc_encrypt(ctx->enc_key, iv, plaintext, plaintext_len,
                           &ciphertext, &ciphertext_len)) {
                return 0;
            }
            break;
        case MODE_CTR:
            if (!ctr_encrypt(ctx->enc_key, iv, plaintext, plaintext_len,
                           &ciphertext, &ciphertext_len)) {
                return 0;
            }
            break;
        case MODE_CFB:
            if (!cfb_encrypt(ctx->enc_key, iv, plaintext, plaintext_len,
                           &ciphertext, &ciphertext_len)) {
                return 0;
            }
            break;
        case MODE_OFB:
            if (!ofb_encrypt(ctx->enc_key, iv, plaintext, plaintext_len,
                           &ciphertext, &ciphertext_len)) {
                return 0;
            }
            break;
        default:
            fprintf(stderr, "Error: Unsupported mode for ETM encryption\n");
            return 0;
    }

    size_t mac_input_len = IV_SIZE + ciphertext_len + aad_len;
    BYTE *mac_input = malloc(mac_input_len);
    if (!mac_input) {
        free(ciphertext);
        return 0;
    }

    memcpy(mac_input, iv, IV_SIZE);
    memcpy(mac_input + IV_SIZE, ciphertext, ciphertext_len);
    if (aad_len > 0) {
        memcpy(mac_input + IV_SIZE + ciphertext_len, aad, aad_len);
    }

    BYTE mac[HMAC_DIGEST_SIZE];
    hmac_compute(ctx->mac_key, HMAC_DIGEST_SIZE,
                mac_input, mac_input_len,
                mac);

    free(mac_input);

    *output_len = IV_SIZE + ciphertext_len + HMAC_DIGEST_SIZE;
    *output = malloc(*output_len);
    if (!*output) {
        free(ciphertext);
        return 0;
    }

    memcpy(*output, iv, IV_SIZE);
    memcpy(*output + IV_SIZE, ciphertext, ciphertext_len);
    memcpy(*output + IV_SIZE + ciphertext_len, mac, HMAC_DIGEST_SIZE);

    free(ciphertext);
    return 1;
}

int etm_decrypt(etm_ctx_t *ctx,
               const BYTE *input, size_t input_len,
               const BYTE *aad, size_t aad_len,
               BYTE **output, size_t *output_len) {
    if (!ctx || !input || !output || !output_len) return 0;

    if (input_len < IV_SIZE + 1 + HMAC_DIGEST_SIZE) {
        fprintf(stderr, "Error: Input too short for ETM decryption\n");
        return 0;
    }

    const BYTE *iv = input;
    size_t ciphertext_len = input_len - IV_SIZE - HMAC_DIGEST_SIZE;
    const BYTE *ciphertext = input + IV_SIZE;
    const BYTE *mac = input + IV_SIZE + ciphertext_len;

    size_t mac_input_len = IV_SIZE + ciphertext_len + aad_len;
    BYTE *mac_input = malloc(mac_input_len);
    if (!mac_input) return 0;

    memcpy(mac_input, iv, IV_SIZE);
    memcpy(mac_input + IV_SIZE, ciphertext, ciphertext_len);
    if (aad_len > 0) {
        memcpy(mac_input + IV_SIZE + ciphertext_len, aad, aad_len);
    }

    BYTE computed_mac[HMAC_DIGEST_SIZE];
    hmac_compute(ctx->mac_key, HMAC_DIGEST_SIZE,
                mac_input, mac_input_len,
                computed_mac);

    free(mac_input);

    int mac_valid = 1;
    for (size_t i = 0; i < HMAC_DIGEST_SIZE; i++) {
        mac_valid &= (computed_mac[i] == mac[i]);
    }

    if (!mac_valid) {
        fprintf(stderr, "Error: ETM authentication failed\n");
        return 0;
    }

    switch(ctx->enc_mode) {
        case MODE_CBC:
            if (!cbc_decrypt(ctx->enc_key, iv, ciphertext, ciphertext_len,
                           output, output_len)) {
                return 0;
            }
            break;
        case MODE_CTR:
            if (!ctr_decrypt(ctx->enc_key, iv, ciphertext, ciphertext_len,
                           output, output_len)) {
                return 0;
            }
            break;
        case MODE_CFB:
            if (!cfb_decrypt(ctx->enc_key, iv, ciphertext, ciphertext_len,
                           output, output_len)) {
                return 0;
            }
            break;
        case MODE_OFB:
            if (!ofb_decrypt(ctx->enc_key, iv, ciphertext, ciphertext_len,
                           output, output_len)) {
                return 0;
            }
            break;
        default:
            fprintf(stderr, "Error: Unsupported mode for ETM decryption\n");
            return 0;
    }

    return 1;
}

void etm_cleanup(etm_ctx_t *ctx) {
    if (ctx) {
        memset(ctx->enc_key, 0, AES_128_KEY_SIZE);
        memset(ctx->mac_key, 0, HMAC_DIGEST_SIZE);
    }
}

int encrypt_then_mac(cipher_mode_t enc_mode,
                     const BYTE *key, size_t key_len,
                     const BYTE *plaintext, size_t plaintext_len,
                     const BYTE *aad, size_t aad_len,
                     BYTE **output, size_t *output_len) {

    etm_ctx_t ctx;
    if (!etm_init(&ctx, enc_mode, key, key_len)) {
        return 0;
    }

    int result = etm_encrypt(&ctx, plaintext, plaintext_len,
                           aad, aad_len, output, output_len);

    etm_cleanup(&ctx);
    return result;
}

int decrypt_then_verify(cipher_mode_t enc_mode,
                        const BYTE *key, size_t key_len,
                        const BYTE *input, size_t input_len,
                        const BYTE *aad, size_t aad_len,
                        BYTE **output, size_t *output_len) {

    etm_ctx_t ctx;
    if (!etm_init(&ctx, enc_mode, key, key_len)) {
        return 0;
    }

    int result = etm_decrypt(&ctx, input, input_len,
                           aad, aad_len, output, output_len);

    etm_cleanup(&ctx);
    return result;
}
