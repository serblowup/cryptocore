/*
 * cfb.c
 *
 *  Created on: 28 сент. 2025 г.
 *      Author: sergey
 */

#include "../include/main.h"
#include <openssl/evp.h>
#include <openssl/err.h>

int cfb_encrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len) {
    EVP_CIPHER_CTX *ctx;
    BYTE keystream[BLOCK_SIZE];
    BYTE feedback[BLOCK_SIZE];
    size_t bytes_processed = 0;
    int len;

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

    while (bytes_processed < input_len) {
        if (1 != EVP_EncryptUpdate(ctx, keystream, &len, feedback, BLOCK_SIZE)) {
            EVP_CIPHER_CTX_free(ctx);
            free(*output);
            return 0;
        }

        size_t bytes_to_process = (input_len - bytes_processed < BLOCK_SIZE) ?
                                 input_len - bytes_processed : BLOCK_SIZE;

        for (size_t i = 0; i < bytes_to_process; i++) {
            (*output)[bytes_processed + i] = input[bytes_processed + i] ^ keystream[i];
        }

        if (bytes_to_process == BLOCK_SIZE) {
            memcpy(feedback, *output + bytes_processed, BLOCK_SIZE);
        } else {
            memmove(feedback, feedback + bytes_to_process, BLOCK_SIZE - bytes_to_process);
            memcpy(feedback + BLOCK_SIZE - bytes_to_process, *output + bytes_processed, bytes_to_process);
        }

        bytes_processed += bytes_to_process;
    }

    EVP_CIPHER_CTX_free(ctx);
    *output_len = input_len;
    return 1;
}

int cfb_decrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len) {
    EVP_CIPHER_CTX *ctx;
    BYTE keystream[BLOCK_SIZE];
    BYTE feedback[BLOCK_SIZE];
    size_t bytes_processed = 0;
    int len;

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

    while (bytes_processed < input_len) {
        if (1 != EVP_EncryptUpdate(ctx, keystream, &len, feedback, BLOCK_SIZE)) {
            EVP_CIPHER_CTX_free(ctx);
            free(*output);
            return 0;
        }

        size_t bytes_to_process = (input_len - bytes_processed < BLOCK_SIZE) ?
                                 input_len - bytes_processed : BLOCK_SIZE;

        for (size_t i = 0; i < bytes_to_process; i++) {
            (*output)[bytes_processed + i] = input[bytes_processed + i] ^ keystream[i];
        }

        if (bytes_to_process == BLOCK_SIZE) {
            memcpy(feedback, input + bytes_processed, BLOCK_SIZE);
        } else {
            memmove(feedback, feedback + bytes_to_process, BLOCK_SIZE - bytes_to_process);
            memcpy(feedback + BLOCK_SIZE - bytes_to_process, input + bytes_processed, bytes_to_process);
        }

        bytes_processed += bytes_to_process;
    }

    EVP_CIPHER_CTX_free(ctx);
    *output_len = input_len;
    return 1;
}
