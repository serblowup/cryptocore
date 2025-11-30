/*
 * cmac.c
 *
 *  Created on: 29 нояб. 2025 г.
 *      Author: sergey
 */

#include "../include/cmac.h"
#include "../include/main.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const BYTE Rb_128[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
};

static void left_shift_one_bit(const BYTE *input, BYTE *output) {
    int carry = 0;
    for (int i = CMAC_BLOCK_SIZE - 1; i >= 0; i--) {
        int new_carry = (input[i] & 0x80) ? 1 : 0;
        output[i] = (input[i] << 1) | carry;
        carry = new_carry;
    }
}

static void cmac_xor_blocks(const BYTE *a, const BYTE *b, BYTE *result) {
    for (int i = 0; i < CMAC_BLOCK_SIZE; i++) {
        result[i] = a[i] ^ b[i];
    }
}

static int aes_encrypt(const BYTE *key, const BYTE *input, BYTE *output) {
    BYTE *ecb_output = NULL;
    size_t output_len;

    if (!ecb_encrypt_no_padding(key, input, CMAC_BLOCK_SIZE, &ecb_output, &output_len)) {
        return 0;
    }

    if (output_len != CMAC_BLOCK_SIZE) {
        free(ecb_output);
        return 0;
    }

    memcpy(output, ecb_output, CMAC_BLOCK_SIZE);
    free(ecb_output);
    return 1;
}

void cmac_generate_subkeys(const BYTE *key, BYTE *k1, BYTE *k2) {
    BYTE L[CMAC_BLOCK_SIZE];
    BYTE temp[CMAC_BLOCK_SIZE];

    memset(L, 0, CMAC_BLOCK_SIZE);
    if (!aes_encrypt(key, L, L)) {
        fprintf(stderr, "Error: CMAC subkey generation failed at L computation\n");
        return;
    }

    left_shift_one_bit(L, temp);
    if (L[0] & 0x80) {
        cmac_xor_blocks(temp, Rb_128, k1);
    } else {
        memcpy(k1, temp, CMAC_BLOCK_SIZE);
    }

    left_shift_one_bit(k1, temp);
    if (k1[0] & 0x80) {
        cmac_xor_blocks(temp, Rb_128, k2);
    } else {
        memcpy(k2, temp, CMAC_BLOCK_SIZE);
    }
}

int cmac_compute(const BYTE *key, const BYTE *data, size_t data_len, BYTE *digest) {
    BYTE k1[CMAC_BLOCK_SIZE], k2[CMAC_BLOCK_SIZE];
    BYTE block[CMAC_BLOCK_SIZE];
    BYTE cipher[CMAC_BLOCK_SIZE];
    size_t n, i;

    cmac_generate_subkeys(key, k1, k2);

    n = (data_len + CMAC_BLOCK_SIZE - 1) / CMAC_BLOCK_SIZE;
    if (n == 0) n = 1;

    memset(cipher, 0, CMAC_BLOCK_SIZE);

    for (i = 0; i < n - 1; i++) {
        memcpy(block, data + i * CMAC_BLOCK_SIZE, CMAC_BLOCK_SIZE);
        cmac_xor_blocks(block, cipher, block);
        if (!aes_encrypt(key, block, cipher)) {
            fprintf(stderr, "Error: CMAC computation failed at block %zu\n", i);
            return 0;
        }
    }

    size_t last_block_len = data_len - (n - 1) * CMAC_BLOCK_SIZE;
    const BYTE *last_block_data = data + (n - 1) * CMAC_BLOCK_SIZE;

    if (last_block_len == CMAC_BLOCK_SIZE) {
        memcpy(block, last_block_data, CMAC_BLOCK_SIZE);
        cmac_xor_blocks(block, k1, block);
    } else {
        memcpy(block, last_block_data, last_block_len);
        block[last_block_len] = 0x80;
        memset(block + last_block_len + 1, 0, CMAC_BLOCK_SIZE - last_block_len - 1);
        cmac_xor_blocks(block, k2, block);
    }

    cmac_xor_blocks(block, cipher, block);
    if (!aes_encrypt(key, block, cipher)) {
        fprintf(stderr, "Error: CMAC computation failed at final block\n");
        return 0;
    }

    memcpy(digest, cipher, CMAC_DIGEST_SIZE);
    return 1;
}

int cmac_verify(const BYTE *key, const BYTE *data, size_t data_len, const BYTE *expected_digest) {
    BYTE computed_digest[CMAC_DIGEST_SIZE];
    if (!cmac_compute(key, data, data_len, computed_digest)) {
        return 0;
    }
    return memcmp(computed_digest, expected_digest, CMAC_DIGEST_SIZE) == 0;
}

int cmac_file_compute(const BYTE *key, const char *filename, BYTE *digest) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file '%s'\n", filename);
        return 0;
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    BYTE *file_data = malloc(file_size);
    if (!file_data) {
        fclose(file);
        return 0;
    }

    if (fread(file_data, 1, file_size, file) != file_size) {
        fprintf(stderr, "Error: Cannot read file '%s'\n", filename);
        free(file_data);
        fclose(file);
        return 0;
    }

    int result = cmac_compute(key, file_data, file_size, digest);

    free(file_data);
    fclose(file);

    if (result) {
        printf("CMAC computed for %zu bytes from '%s'\n", file_size, filename);
    } else {
        fprintf(stderr, "Error: CMAC computation failed for file '%s'\n", filename);
    }

    return result;
}
