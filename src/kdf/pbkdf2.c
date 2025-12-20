/*
 * pbkdf2.c
 *
 *  Created on: 20 дек. 2025 г.
 *      Author: sergey
 */

#include "../../include/pbkdf2.h"
#include "../../include/hmac.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static void int_to_big_endian(unsigned int i, BYTE *output) {
    output[0] = (i >> 24) & 0xFF;
    output[1] = (i >> 16) & 0xFF;
    output[2] = (i >> 8) & 0xFF;
    output[3] = i & 0xFF;
}

int pbkdf2_hmac_sha256(const BYTE *password, size_t password_len,
                       const BYTE *salt, size_t salt_len,
                       unsigned int iterations,
                       size_t dklen,
                       BYTE *derived_key) {
    if (!password || !salt || !derived_key || dklen == 0) {
        return 0;
    }

    size_t blocks_needed = (dklen + 31) / 32;

    BYTE *T = malloc(blocks_needed * 32);
    if (!T) {
        return 0;
    }

    for (size_t i = 1; i <= blocks_needed; i++) {
        BYTE U[32];
        BYTE T_i[32];

        BYTE *S_i = malloc(salt_len + 4);
        if (!S_i) {
            free(T);
            return 0;
        }

        memcpy(S_i, salt, salt_len);
        int_to_big_endian((unsigned int)i, S_i + salt_len);

        hmac_compute(password, password_len, S_i, salt_len + 4, U);
        memcpy(T_i, U, 32);

        for (unsigned int j = 2; j <= iterations; j++) {
            hmac_compute(password, password_len, U, 32, U);

            for (int k = 0; k < 32; k++) {
                T_i[k] ^= U[k];
            }
        }

        memcpy(T + (i-1)*32, T_i, 32);

        free(S_i);
    }

    memcpy(derived_key, T, dklen);

    free(T);
    return 1;
}
