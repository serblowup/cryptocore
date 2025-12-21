/*
 * ofb.c
 *
 *  Created on: 28 сент. 2025 г.
 *      Author: sergey
 */

#include "../include/main.h"
#include <openssl/evp.h>
#include <openssl/err.h>

int ofb_encrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len) {
    EVP_CIPHER_CTX *ctx;
    BYTE keystream[BLOCK_SIZE];
    BYTE feedback[BLOCK_SIZE];
    size_t bytes_processed;

    *output = malloc(input_len);
    if (!*output) {
        return 0;
    }

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        free(*output);
        return 0;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return 0;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    memcpy(feedback, iv, BLOCK_SIZE);
    bytes_processed = 0;

    while (bytes_processed < input_len) {
        int len;
        if (1 != EVP_EncryptUpdate(ctx, keystream, &len, feedback, BLOCK_SIZE)) {
            EVP_CIPHER_CTX_free(ctx);
            free(*output);
            return 0;
        }

        memcpy(feedback, keystream, BLOCK_SIZE);

        size_t bytes_to_process = (input_len - bytes_processed < BLOCK_SIZE) ?
                                 input_len - bytes_processed : BLOCK_SIZE;

        for (size_t i = 0; i < bytes_to_process; i++) {
            (*output)[bytes_processed + i] = input[bytes_processed + i] ^ keystream[i];
        }

        bytes_processed += bytes_to_process;
    }

    EVP_CIPHER_CTX_free(ctx);
    *output_len = input_len;
    return 1;
}

int ofb_decrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len) {
    return ofb_encrypt(key, iv, input, input_len, output, output_len);
}

int ofb_encrypt_no_padding(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create cipher context\n");
        return 0;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error: Failed to initialize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    *output = malloc(input_len);
    if (!*output) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int out_len;
    if (EVP_EncryptUpdate(ctx, *output, &out_len, input, (int)input_len) != 1) {
        fprintf(stderr, "Error: Encryption failed\n");
        free(*output);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int final_len;
    if (EVP_EncryptFinal_ex(ctx, *output + out_len, &final_len) != 1) {
        fprintf(stderr, "Error: Encryption finalization failed\n");
        free(*output);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    *output_len = (size_t)(out_len + final_len);

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int ofb_decrypt_no_padding(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len) {
    return ofb_encrypt_no_padding(key, iv, input, input_len, output, output_len);
}
