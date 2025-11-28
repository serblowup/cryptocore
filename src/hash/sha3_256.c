/*
 * sha3_256.c
 *
 *  Created on: 27 нояб. 2025 г.
 *      Author: sergey
 */

#include "../../include/sha3_256.h"
#include <openssl/evp.h>

int sha3_256_hash(const BYTE *data, size_t len, BYTE *digest) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return 0;
    }

    int success = 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) != 1) {
        goto cleanup;
    }

    if (EVP_DigestUpdate(ctx, data, len) != 1) {
        goto cleanup;
    }

    unsigned int digest_len;
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        goto cleanup;
    }

    if (digest_len != SHA3_256_DIGEST_SIZE) {
        goto cleanup;
    }

    success = 1;

cleanup:
    EVP_MD_CTX_free(ctx);
    return success;
}
