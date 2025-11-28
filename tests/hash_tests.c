/*
 * hash_tests.c
 *
 *  Created on: 27 нояб. 2025 г.
 *      Author: sergey
 */

#include "../include/main.h"
#include "../include/sha256.h"
#include "../include/sha3_256.h"
#include <string.h>
#include <openssl/evp.h>

static const struct {
    const char *input;
    const char *sha256_expected;
    const char *sha3_256_expected;
} test_vectors[] = {
    {
        "",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    },
    {
        "abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    },
    {
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"
    }
};

static int test_known_answers(void) {
    printf("Known-Answer Tests (NIST Vectors)\n");

    int all_passed = 1;

    for (size_t i = 0; i < sizeof(test_vectors) / sizeof(test_vectors[0]); i++) {
        BYTE digest[32];
        char hex_digest[65];
        int test_passed = 1;

        sha256_hash((const BYTE*)test_vectors[i].input,
                   strlen(test_vectors[i].input), digest);

        for (int j = 0; j < 32; j++) {
            sprintf(hex_digest + (j * 2), "%02x", digest[j]);
        }
        hex_digest[64] = '\0';

        if (strcmp(hex_digest, test_vectors[i].sha256_expected) != 0) {
            printf("Fail: SHA-256 test %zu\n", i);
            printf("  Input: '%s'\n", test_vectors[i].input);
            printf("  Expected: %s\n", test_vectors[i].sha256_expected);
            printf("  Got:      %s\n", hex_digest);
            test_passed = 0;
            all_passed = 0;
        }

        if (!sha3_256_hash((const BYTE*)test_vectors[i].input,
                          strlen(test_vectors[i].input), digest)) {
            printf("Fail: SHA3-256 computation failed for test %zu\n", i);
            test_passed = 0;
            all_passed = 0;
        } else {
            for (int j = 0; j < 32; j++) {
                sprintf(hex_digest + (j * 2), "%02x", digest[j]);
            }
            hex_digest[64] = '\0';

            if (strcmp(hex_digest, test_vectors[i].sha3_256_expected) != 0) {
                printf("Fail: SHA3-256 test %zu\n", i);
                printf("  Input: '%s'\n", test_vectors[i].input);
                printf("  Expected: %s\n", test_vectors[i].sha3_256_expected);
                printf("  Got:      %s\n", hex_digest);
                test_passed = 0;
                all_passed = 0;
            }
        }

        if (test_passed) {
            printf("Pass: Test %zu - Input: '%s'\n", i, test_vectors[i].input);
        }
    }

    return all_passed;
}

static int test_empty_file(void) {
    printf("\nEmpty File Test\n");

    const char *filename = "empty_test.tmp";
    FILE *file = fopen(filename, "wb");
    if (!file) {
        printf("Fail: Cannot create empty test file\n");
        return 0;
    }
    fclose(file);

    BYTE *data = NULL;
    size_t len;
    if (!read_file(filename, &data, &len)) {
        printf("Fail: Cannot read empty test file\n");
        remove(filename);
        return 0;
    }

    BYTE sha256_digest[32], sha3_digest[32];
    sha256_hash(data, len, sha256_digest);
    sha3_256_hash(data, len, sha3_digest);

    char sha256_hex[65], sha3_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(sha256_hex + (i * 2), "%02x", sha256_digest[i]);
        sprintf(sha3_hex + (i * 2), "%02x", sha3_digest[i]);
    }
    sha256_hex[64] = sha3_hex[64] = '\0';

    int passed = 1;
    if (strcmp(sha256_hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") != 0) {
        printf("Fail: SHA-256 empty file test\n");
        printf("  Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n");
        printf("  Got:      %s\n", sha256_hex);
        passed = 0;
    }

    if (strcmp(sha3_hex, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a") != 0) {
        printf("Fail: SHA3-256 empty file test\n");
        printf("  Expected: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a\n");
        printf("  Got:      %s\n", sha3_hex);
        passed = 0;
    }

    if (passed) {
        printf("Pass: Empty file test\n");
    }

    free(data);
    remove(filename);
    return passed;
}

static int test_avalanche_effect(void) {
    printf("\nAvalanche Effect Test\n");

    BYTE original_data[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                              0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    BYTE modified_data[16];
    memcpy(modified_data, original_data, 16);

    modified_data[15] ^= 0x01;

    BYTE hash1[32], hash2[32];
    sha256_hash(original_data, 16, hash1);
    sha256_hash(modified_data, 16, hash2);

    int diff_count = 0;
    for (int i = 0; i < 32; i++) {
        BYTE xor = hash1[i] ^ hash2[i];
        while (xor) {
            diff_count += (xor & 1);
            xor >>= 1;
        }
    }

    printf("Bits changed in SHA-256: %d/256 (%.1f%%)\n", diff_count, (diff_count * 100.0) / 256);

    int passed = (diff_count > 100 && diff_count < 156);

    if (passed) {
        printf("Pass: Avalanche effect test - %d bits changed\n", diff_count);
    } else {
        printf("Fail: Weak avalanche effect - only %d bits changed\n", diff_count);
    }

    return passed;
}

static int test_large_file(void) {
    printf("\nLarge File Test\n");

    const char *filename = "large_test.tmp";
    const size_t file_size = 1024 * 1024; // 1MB

    FILE *file = fopen(filename, "wb");
    if (!file) {
        printf("Fail: Cannot create large test file\n");
        return 0;
    }

    BYTE pattern[256];
    for (int i = 0; i < 256; i++) {
        pattern[i] = i;
    }

    for (size_t i = 0; i < file_size; i += 256) {
        fwrite(pattern, 1, 256, file);
    }
    fclose(file);

    BYTE *data = NULL;
    size_t len;
    if (!read_file(filename, &data, &len)) {
        printf("Fail: Cannot read large test file\n");
        remove(filename);
        return 0;
    }

    BYTE sha256_digest[32], sha3_digest[32];
    sha256_hash(data, len, sha256_digest);
    sha3_256_hash(data, len, sha3_digest);

    printf("Pass: Large file (%zu bytes) processed successfully\n", len);
    printf("  SHA-256: ");
    for (int i = 0; i < 32; i++) printf("%02x", sha256_digest[i]);
    printf("\n");
    printf("  SHA3-256: ");
    for (int i = 0; i < 32; i++) printf("%02x", sha3_digest[i]);
    printf("\n");

    free(data);
    remove(filename);
    return 1;
}

static int test_chunk_processing(void) {
    printf("\nChunk Processing Test\n");

    const char *filename = "chunk_test.tmp";
    const size_t file_size = 5 * 1024 * 1024; // 5MB
    const size_t chunk_sizes[] = {4096, 8192, 16384};
    const size_t num_chunk_sizes = sizeof(chunk_sizes) / sizeof(chunk_sizes[0]);

    FILE *file = fopen(filename, "wb");
    if (!file) {
        printf("Fail: Cannot create test file\n");
        return 0;
    }

    BYTE *random_data = malloc(65536);
    if (!random_data) {
        fclose(file);
        return 0;
    }

    for (size_t i = 0; i < file_size; i += 65536) {
        if (generate_random_bytes(random_data, 65536) != 1) {
            printf("Fail: Cannot generate random data\n");
            free(random_data);
            fclose(file);
            return 0;
        }
        fwrite(random_data, 1, 65536, file);
    }
    free(random_data);
    fclose(file);

    int all_passed = 1;

    for (size_t i = 0; i < num_chunk_sizes; i++) {
        BYTE chunk_digest[32], normal_digest[32];

        if (!sha256_file_hash(filename, chunk_digest, chunk_sizes[i])) {
            printf("Fail: Chunk processing failed for chunk size %zu\n", chunk_sizes[i]);
            all_passed = 0;
            continue;
        }

        BYTE *file_data = NULL;
        size_t file_len;
        if (!read_file(filename, &file_data, &file_len)) {
            printf("Fail: Cannot read file for normal hashing\n");
            all_passed = 0;
            continue;
        }

        sha256_hash(file_data, file_len, normal_digest);
        free(file_data);

        if (memcmp(chunk_digest, normal_digest, 32) != 0) {
            printf("Fail: Chunk processing mismatch for chunk size %zu\n", chunk_sizes[i]);
            all_passed = 0;
        } else {
            printf("Pass: Chunk size %zu bytes\n", chunk_sizes[i]);
        }
    }

    remove(filename);
    return all_passed;
}

int run_hash_tests(void) {
    printf("Running Hash Function Tests...\n\n");

    int success = 1;

    success &= test_known_answers();
    success &= test_empty_file();
    success &= test_avalanche_effect();
    success &= test_large_file();
    success &= test_chunk_processing();

    printf("\n");
    printf("HASH TESTS %s\n", success ? "PASSED" : "FAILED");

    return success;
}
