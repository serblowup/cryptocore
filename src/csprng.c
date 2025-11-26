/*
 * csprng.c
 *
 *  Created on: 9 нояб. 2025 г.
 *      Author: sergey
 */

#include "../include/main.h"
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>

#define CSPRNG_SUCCESS 1
#define CSPRNG_ERROR 0

int generate_random_bytes(uint8_t* buffer, size_t num_bytes) {
    if (buffer == NULL || num_bytes == 0) {
        fprintf(stderr, "Error: Invalid parameters for generate_random_bytes\n");
        return CSPRNG_ERROR;
    }

    if (RAND_bytes(buffer, num_bytes) != 1) {
        unsigned long error_code = ERR_get_error();
        const char* error_str = ERR_reason_error_string(error_code);

        fprintf(stderr, "Error: RAND_bytes failed - ");
        if (error_str) {
            fprintf(stderr, "%s (error %lu)\n", error_str, error_code);
        } else {
            fprintf(stderr, "Unknown error %lu\n", error_code);
        }
        return CSPRNG_ERROR;
    }

    return CSPRNG_SUCCESS;
}


int generate_random_key(BYTE* key) {
    return generate_random_bytes(key, AES_128_KEY_SIZE);
}

int is_weak_key(const BYTE* key, size_t key_len) {
    if (key == NULL) return 1;

    int all_zeros = 1;
    int all_ones = 1;
    int sequential_inc = 1;
    int sequential_dec = 1;

    for (size_t i = 0; i < key_len; i++) {
        if (key[i] != 0x00) all_zeros = 0;
        if (key[i] != 0xFF) all_ones = 0;

        if (i > 0) {
            if (key[i] != key[i-1] + 1) sequential_inc = 0;
            if (key[i] != key[i-1] - 1) sequential_dec = 0;
        }
    }

    return all_zeros || all_ones || sequential_inc || sequential_dec;
}

