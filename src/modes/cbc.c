/*
 * cbc.c
 *
 *  Created on: 28 сент. 2025 г.
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

    if (pad_value == 0 || pad_value > BLOCK_SIZE) {
        return data_len;
    }

    for (size_t i = data_len - pad_value; i < data_len; i++) {
        if (data[i] != pad_value) {
            return data_len;
        }
    }
    return data_len - pad_value;
}

int cbc_encrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    size_t padded_len;
    BYTE *padded_input = NULL;

    padded_len = input_len + (BLOCK_SIZE - (input_len % BLOCK_SIZE));
    if (padded_len == input_len) {
        padded_len += BLOCK_SIZE;
    }

    padded_input = malloc(padded_len);
    if (!padded_input) {
        return 0;
    }
    memcpy(padded_input, input, input_len);
    add_padding(padded_input, input_len, BLOCK_SIZE);

    *output = malloc(padded_len);
    if (!*output) {
        free(padded_input);
        return 0;
    }

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        free(padded_input);
        free(*output);
        return 0;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        free(padded_input);
        free(*output);
        return 0;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    BYTE block[BLOCK_SIZE];
    BYTE prev_block[BLOCK_SIZE];
    memcpy(prev_block, iv, BLOCK_SIZE);

    for (size_t i = 0; i < padded_len; i += BLOCK_SIZE) {
        xor_blocks(padded_input + i, prev_block, block, BLOCK_SIZE);

        if (1 != EVP_EncryptUpdate(ctx, *output + i, &len, block, BLOCK_SIZE)) {
            EVP_CIPHER_CTX_free(ctx);
            free(padded_input);
            free(*output);
            return 0;
        }

        memcpy(prev_block, *output + i, BLOCK_SIZE);
    }

    EVP_CIPHER_CTX_free(ctx);
    free(padded_input);
    *output_len = padded_len;
    return 1;
}

int cbc_decrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    BYTE decrypted_block[BLOCK_SIZE];
    BYTE prev_block[BLOCK_SIZE];

    if (input_len % BLOCK_SIZE != 0) {
        fprintf(stderr, "Error: Input length must be multiple of block size\n");
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

    memcpy(prev_block, iv, BLOCK_SIZE);

    for (size_t i = 0; i < input_len; i += BLOCK_SIZE) {
        if (1 != EVP_DecryptUpdate(ctx, decrypted_block, &len, input + i, BLOCK_SIZE)) {
            EVP_CIPHER_CTX_free(ctx);
            free(*output);
            return 0;
        }

        xor_blocks(decrypted_block, prev_block, *output + i, BLOCK_SIZE);

        memcpy(prev_block, input + i, BLOCK_SIZE);
    }

    EVP_CIPHER_CTX_free(ctx);

    *output_len = remove_padding(*output, input_len);
    return 1;
}

