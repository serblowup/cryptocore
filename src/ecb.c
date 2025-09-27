/*
 * ecb.c
 *
 *  Created on: 27 сент. 2025 г.
 *      Author: sergey
 */

#include "../include/main.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

static void add_padding(BYTE *data, size_t data_len, size_t block_size) {
    BYTE pad_value = block_size - (data_len % block_size);
    for (size_t i = 0; i < pad_value; i++) {
        data[data_len + i] = pad_value;
    }
}

static size_t remove_padding(const BYTE *data, size_t data_len) {
    if (data_len == 0) return 0;

    BYTE pad_value = data[data_len - 1];
    if (pad_value > BLOCK_SIZE || pad_value == 0) {
        return data_len;
    }

    for (size_t i = data_len - pad_value; i < data_len; i++) {
        if (data[i] != pad_value) {
            return data_len;
        }
    }

    return data_len - pad_value;
}

int ecb_encrypt(const BYTE *key, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    size_t padded_len;

    padded_len = input_len + (BLOCK_SIZE - (input_len % BLOCK_SIZE));
    if (padded_len == input_len) {
        padded_len += BLOCK_SIZE;
    }

    *output = malloc(padded_len);
    if (!*output) {
        return 0;
    }

    memcpy(*output, input, input_len);
    add_padding(*output, input_len, BLOCK_SIZE);

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

    if (1 != EVP_EncryptUpdate(ctx, *output, &len, *output, padded_len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return 0;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, *output + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return 0;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    *output_len = ciphertext_len;
    return 1;
}

int ecb_decrypt(const BYTE *key, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (input_len % BLOCK_SIZE != 0) {
        return 0;
    }

    *output = malloc(input_len);
    if (!*output) {
        return 0;
    }

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        free(*output);
        return 0;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return 0;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (1 != EVP_DecryptUpdate(ctx, *output, &len, input, input_len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return 0;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, *output + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(*output);
        return 0;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    *output_len = remove_padding(*output, plaintext_len);
    return 1;
}

