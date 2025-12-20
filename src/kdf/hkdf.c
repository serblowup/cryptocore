/*
 * hkdf.c
 *
 *  Created on: 20 дек. 2025 г.
 *      Author: sergey
 */

#include "../../include/hkdf.h"
#include "../../include/hmac.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int derive_key_from_master(const BYTE *master_key, size_t master_key_len,
                          const char *context,
                          size_t derived_key_len,
                          BYTE *derived_key) {
    if (!master_key || !context || !derived_key || derived_key_len == 0) {
        return 0;
    }

    size_t context_len = strlen(context);
    size_t derived_bytes = 0;
    unsigned int counter = 1;

    while (derived_bytes < derived_key_len) {
        BYTE *input = malloc(context_len + 4);
        if (!input) {
            return 0;
        }

        memcpy(input, context, context_len);
        input[context_len] = (counter >> 24) & 0xFF;
        input[context_len + 1] = (counter >> 16) & 0xFF;
        input[context_len + 2] = (counter >> 8) & 0xFF;
        input[context_len + 3] = counter & 0xFF;

        BYTE block[32];
        hmac_compute(master_key, master_key_len, input, context_len + 4, block);

        size_t bytes_to_copy = derived_key_len - derived_bytes;
        if (bytes_to_copy > 32) {
            bytes_to_copy = 32;
        }

        memcpy(derived_key + derived_bytes, block, bytes_to_copy);
        derived_bytes += bytes_to_copy;
        counter++;

        free(input);
    }

    return 1;
}
