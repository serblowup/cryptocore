/*
 * all_unit_tests.c
 *
 *  Created on: 21 дек. 2025 г.
 *      Author: sergey
 */

#include "../../include/main.h"
#include "../../include/sha256.h"
#include "../../include/sha3_256.h"
#include "../../include/hmac.h"
#include "../../include/cmac.h"
#include "../../include/pbkdf2.h"
#include "../../include/hkdf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

static int test_aes_ecb_single_block(void) {
    printf("Test AES ECB Single Block... ");

    BYTE key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    BYTE plaintext[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    BYTE *ciphertext = NULL;
    BYTE *decrypted = NULL;
    size_t ciphertext_len, decrypted_len;
    int success = 0;

    if (!ecb_encrypt_no_padding(key, plaintext, 16, &ciphertext, &ciphertext_len)) {
        printf("Encryption failed\n");
        return 0;
    }

    if (ciphertext_len != 16) {
        printf("Wrong ciphertext length: %zu\n", ciphertext_len);
        free(ciphertext);
        return 0;
    }

    if (!ecb_decrypt(key, ciphertext, ciphertext_len, &decrypted, &decrypted_len)) {
        printf("Decryption failed\n");
        free(ciphertext);
        return 0;
    }

    if (decrypted_len != 16) {
        printf("Wrong decrypted length: %zu\n", decrypted_len);
        goto cleanup;
    }

    if (memcmp(plaintext, decrypted, 16) != 0) {
        printf("Decryption mismatch\n");
        goto cleanup;
    }

    success = 1;
    printf("[OK]\n");

cleanup:
    if (ciphertext) free(ciphertext);
    if (decrypted) free(decrypted);
    return success;
}

static int test_aes_key_expansion(void) {
    printf("Test AES Key Consistency... ");

    BYTE key[16];
    BYTE plaintext[16] = {0};
    BYTE *ciphertext1 = NULL, *ciphertext2 = NULL;
    size_t len1, len2;
    int success = 0;

    if (generate_random_key(key) != 1) {
        printf("Key generation failed\n");
        return 0;
    }

    if (!ecb_encrypt_no_padding(key, plaintext, 16, &ciphertext1, &len1)) {
        printf("First encryption failed\n");
        return 0;
    }

    if (!ecb_encrypt_no_padding(key, plaintext, 16, &ciphertext2, &len2)) {
        printf("Second encryption failed\n");
        free(ciphertext1);
        return 0;
    }

    if (len1 != len2 || memcmp(ciphertext1, ciphertext2, len1) != 0) {
        printf("Inconsistent encryption with same key\n");
        goto cleanup;
    }

    success = 1;
    printf("OK\n");

cleanup:
    if (ciphertext1) free(ciphertext1);
    if (ciphertext2) free(ciphertext2);
    return success;
}

static int test_aes_invalid_inputs(void) {
    printf("Test AES Invalid Inputs... ");

    BYTE key[16];
    BYTE plaintext[15];
    BYTE *output = NULL;
    size_t output_len;

    if (generate_random_key(key) != 1) {
        printf("Key generation failed\n");
        return 0;
    }

    memset(plaintext, 0xAA, 15);

    int result = ecb_encrypt_no_padding(key, plaintext, 15, &output, &output_len);
    if (result) {
        printf("Should have failed with 15-byte input\n");
        free(output);
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

int run_aes_unit_tests(void) {
    printf("\nAES Unit Tests\n");

    int success = 1;

    success &= test_aes_ecb_single_block();
    success &= test_aes_key_expansion();
    success &= test_aes_invalid_inputs();

    printf("AES Unit Tests: %s\n", success ? "PASSED" : "FAILED");
    return success;
}

static int test_sha256_single_block(void) {
    printf("Test SHA-256 Single Block... ");

    BYTE data[64];
    memset(data, 0xAA, 64);

    BYTE digest[32];
    sha256_hash(data, 64, digest);

    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (digest[i] != 0) {
            all_zero = 0;
            break;
        }
    }

    if (all_zero) {
        printf("Digest is all zeros\n");
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

static int test_sha256_consistency(void) {
    printf("Test SHA-256 Consistency... ");

    BYTE data[100];
    for (int i = 0; i < 100; i++) {
        data[i] = i;
    }

    BYTE digest1[32], digest2[32];
    sha256_hash(data, 100, digest1);
    sha256_hash(data, 100, digest2);

    if (memcmp(digest1, digest2, 32) != 0) {
        printf("Inconsistent hashing\n");
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

static int test_sha256_empty(void) {
    printf("Test SHA-256 Empty Input... ");

    BYTE digest[32];
    sha256_hash(NULL, 0, digest);

    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (digest[i] != 0) {
            all_zero = 0;
            break;
        }
    }

    if (all_zero) {
        printf("Empty hash is all zeros\n");
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

int run_sha256_unit_tests(void) {
    printf("\nSHA-256 Unit Tests\n");

    int success = 1;

    success &= test_sha256_single_block();
    success &= test_sha256_consistency();
    success &= test_sha256_empty();

    printf("SHA-256 Unit Tests: %s\n", success ? "PASSED" : "FAILED");
    return success;
}

static int test_sha3_256_simple(void) {
    printf("Test SHA3-256 Simple... ");

    BYTE data[] = "test";
    BYTE digest[32];

    if (!sha3_256_hash(data, 4, digest)) {
        printf("Hashing failed\n");
        return 0;
    }

    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (digest[i] != 0) {
            all_zero = 0;
            break;
        }
    }

    if (all_zero) {
        printf("Digest is all zeros\n");
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

static int test_sha3_256_consistency(void) {
    printf("Test SHA3-256 Consistency... ");

    BYTE data[128];
    for (int i = 0; i < 128; i++) {
        data[i] = i * 3;
    }

    BYTE digest1[32], digest2[32];

    if (!sha3_256_hash(data, 128, digest1)) {
        printf("First hash failed\n");
        return 0;
    }

    if (!sha3_256_hash(data, 128, digest2)) {
        printf("Second hash failed\n");
        return 0;
    }

    if (memcmp(digest1, digest2, 32) != 0) {
        printf("Inconsistent hashing\n");
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

int run_sha3_256_unit_tests(void) {
    printf("\nSHA3-256 Unit Tests\n");

    int success = 1;

    success &= test_sha3_256_simple();
    success &= test_sha3_256_consistency();

    printf("SHA3-256 Unit Tests: %s\n", success ? "PASSED" : "FAILED");
    return success;
}

static int test_hmac_consistency(void) {
    printf("Test HMAC Consistency... ");

    BYTE key[16];
    BYTE data[] = "Hello HMAC";
    BYTE digest1[32], digest2[32];

    if (generate_random_bytes(key, 16) != 1) {
        printf("Key generation failed\n");
        return 0;
    }

    hmac_compute(key, 16, data, 10, digest1);
    hmac_compute(key, 16, data, 10, digest2);

    if (memcmp(digest1, digest2, 32) != 0) {
        printf("Inconsistent HMAC\n");
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

static int test_hmac_key_sizes(void) {
    printf("Test HMAC Different Key Sizes... ");

    BYTE short_key[] = "short";
    BYTE long_key[100];
    BYTE data[] = "test";
    BYTE digest[32];

    memset(long_key, 0xBB, 100);

    hmac_compute(short_key, 5, data, 4, digest);
    hmac_compute(long_key, 100, data, 4, digest);

    printf("OK\n");
    return 1;
}

static int test_hmac_verification(void) {
    printf("Test HMAC Verification... ");

    BYTE key[16];
    BYTE data[] = "Verify me";
    BYTE digest[32];

    if (generate_random_bytes(key, 16) != 1) {
        printf("Key generation failed\n");
        return 0;
    }

    hmac_compute(key, 16, data, 9, digest);

    if (!hmac_verify(key, 16, data, 9, digest)) {
        printf("Self-verification failed\n");
        return 0;
    }

    BYTE wrong_key[16];
    memset(wrong_key, 0xAA, 16);

    if (hmac_verify(wrong_key, 16, data, 9, digest)) {
        printf("Should have failed with wrong key\n");
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

int run_hmac_unit_tests(void) {
    printf("\nHMAC Unit Tests\n");

    int success = 1;

    success &= test_hmac_consistency();
    success &= test_hmac_key_sizes();
    success &= test_hmac_verification();

    printf("HMAC Unit Tests: %s\n", success ? "PASSED" : "FAILED");
    return success;
}

static int test_cmac_consistency(void) {
    printf("Test CMAC Consistency... ");

    BYTE key[16];
    BYTE data[] = "Test CMAC consistency";
    BYTE digest1[16], digest2[16];

    if (generate_random_bytes(key, 16) != 1) {
        printf("Key generation failed\n");
        return 0;
    }

    if (!cmac_compute(key, data, 21, digest1)) {
        printf("First CMAC failed\n");
        return 0;
    }

    if (!cmac_compute(key, data, 21, digest2)) {
        printf("Second CMAC failed\n");
        return 0;
    }

    if (memcmp(digest1, digest2, 16) != 0) {
        printf("Inconsistent CMAC\n");
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

static int test_cmac_empty(void) {
    printf("Test CMAC Empty Data... ");

    BYTE key[16];
    BYTE digest[16];

    if (generate_random_bytes(key, 16) != 1) {
        printf("Key generation failed\n");
        return 0;
    }

    if (!cmac_compute(key, NULL, 0, digest)) {
        printf("Empty CMAC failed\n");
        return 0;
    }

    printf("OK\n");
    return 1;
}

static int test_cmac_verification(void) {
    printf("Test CMAC Verification... ");

    BYTE key[16];
    BYTE data[] = "Verify CMAC";
    BYTE digest[16];

    if (generate_random_bytes(key, 16) != 1) {
        printf("Key generation failed\n");
        return 0;
    }

    if (!cmac_compute(key, data, 11, digest)) {
        printf("CMAC computation failed\n");
        return 0;
    }

    if (!cmac_verify(key, data, 11, digest)) {
        printf("Self-verification failed\n");
        return 0;
    }

    BYTE wrong_key[16];
    memset(wrong_key, 0x55, 16);

    if (cmac_verify(wrong_key, data, 11, digest)) {
        printf("Should have failed with wrong key\n");
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

int run_cmac_unit_tests(void) {
    printf("\nCMAC Unit Tests\n");

    int success = 1;

    success &= test_cmac_consistency();
    success &= test_cmac_empty();
    success &= test_cmac_verification();

    printf("CMAC Unit Tests: %s\n", success ? "PASSED" : "FAILED");
    return success;
}

static int test_pbkdf2_consistency(void) {
    printf("Test PBKDF2 Consistency... ");

    BYTE password[] = "test_password";
    BYTE salt[16];
    BYTE derived1[32], derived2[32];

    if (generate_random_bytes(salt, 16) != 1) {
        printf("Salt generation failed\n");
        return 0;
    }

    if (!pbkdf2_hmac_sha256(password, 13, salt, 16, 1000, 32, derived1)) {
        printf("First derivation failed\n");
        return 0;
    }

    if (!pbkdf2_hmac_sha256(password, 13, salt, 16, 1000, 32, derived2)) {
        printf("Second derivation failed\n");
        return 0;
    }

    if (memcmp(derived1, derived2, 32) != 0) {
        printf("Inconsistent PBKDF2\n");
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

static int test_pbkdf2_iteration_effect(void) {
    printf("Test PBKDF2 Iteration Effect... ");

    BYTE password[] = "test";
    BYTE salt[] = "salt";
    BYTE derived1[32], derived2[32];

    if (!pbkdf2_hmac_sha256(password, 4, salt, 4, 100, 32, derived1)) {
        printf("First derivation failed\n");
        return 0;
    }

    if (!pbkdf2_hmac_sha256(password, 4, salt, 4, 1000, 32, derived2)) {
        printf("Second derivation failed\n");
        return 0;
    }

    if (memcmp(derived1, derived2, 32) == 0) {
        printf("Different iterations produced same result\n");
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

static int test_pbkdf2_different_lengths(void) {
    printf("Test PBKDF2 Different Lengths... ");

    BYTE password[] = "password";
    BYTE salt[] = "salt";
    int passed = 1;

    for (size_t len = 1; len <= 64; len += 7) {
        BYTE derived[64];
        if (!pbkdf2_hmac_sha256(password, 8, salt, 4, 100, len, derived)) {
            printf("Failed for length %zu\n", len);
            passed = 0;
            break;
        }
    }

    if (passed) printf("[OK]\n");
    return passed;
}

int run_pbkdf2_unit_tests(void) {
    printf("\nPBKDF2 Unit Tests\n");

    int success = 1;

    success &= test_pbkdf2_consistency();
    success &= test_pbkdf2_iteration_effect();
    success &= test_pbkdf2_different_lengths();

    printf("PBKDF2 Unit Tests: %s\n", success ? "PASSED" : "FAILED");
    return success;
}

static int test_hkdf_consistency(void) {
    printf("Test HKDF Consistency... ");

    BYTE master_key[32];
    const char *context = "test_context";
    BYTE derived1[32], derived2[32];

    memset(master_key, 0xAA, 32);

    if (!derive_key_from_master(master_key, 32, context, 32, derived1)) {
        printf("First derivation failed\n");
        return 0;
    }

    if (!derive_key_from_master(master_key, 32, context, 32, derived2)) {
        printf("Second derivation failed\n");
        return 0;
    }

    if (memcmp(derived1, derived2, 32) != 0) {
        printf("Inconsistent HKDF\n");
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

static int test_hkdf_context_separation(void) {
    printf("Test HKDF Context Separation... ");

    BYTE master_key[32];
    BYTE key1[32], key2[32];

    memset(master_key, 0xBB, 32);

    if (!derive_key_from_master(master_key, 32, "context1", 32, key1)) {
        printf("First derivation failed\n");
        return 0;
    }

    if (!derive_key_from_master(master_key, 32, "context2", 32, key2)) {
        printf("Second derivation failed\n");
        return 0;
    }

    if (memcmp(key1, key2, 32) == 0) {
        printf("Different contexts gave same key\n");
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

static int test_hkdf_lengths(void) {
    printf("Test HKDF Different Lengths... ");

    BYTE master_key[32];
    const char *context = "test";
    int passed = 1;

    memset(master_key, 0xCC, 32);

    for (size_t len = 1; len <= 128; len += 13) {
        BYTE derived[128];
        if (!derive_key_from_master(master_key, 32, context, len, derived)) {
            printf("Failed for length %zu\n", len);
            passed = 0;
            break;
        }
    }

    if (passed) printf("[OK]\n");
    return passed;
}

int run_hkdf_unit_tests(void) {
    printf("\nHKDF Unit Tests\n");

    int success = 1;

    success &= test_hkdf_consistency();
    success &= test_hkdf_context_separation();
    success &= test_hkdf_lengths();

    printf("HKDF Unit Tests: %s\n", success ? "PASSED" : "FAILED");
    return success;
}

static int test_random_bytes_generation(void) {
    printf("Test Random Bytes Generation... ");

    BYTE buffer1[100], buffer2[100];

    if (generate_random_bytes(buffer1, 100) != 1) {
        printf("First generation failed\n");
        return 0;
    }

    if (generate_random_bytes(buffer2, 100) != 1) {
        printf("Second generation failed\n");
        return 0;
    }

    if (memcmp(buffer1, buffer2, 100) == 0) {
        printf("Generated identical buffers (highly unlikely)\n");
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

static int test_random_key_generation(void) {
    printf("Test Random Key Generation... ");

    BYTE key1[16], key2[16];

    if (generate_random_key(key1) != 1) {
        printf("First key generation failed\n");
        return 0;
    }

    if (generate_random_key(key2) != 1) {
        printf("Second key generation failed\n");
        return 0;
    }

    if (is_weak_key(key1, 16)) {
        printf("Generated weak key 1\n");
        return 0;
    }

    if (is_weak_key(key2, 16)) {
        printf("Generated weak key 2\n");
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

static int test_weak_key_detection(void) {
    printf("Test Weak Key Detection... ");

    BYTE all_zeros[16] = {0};
    BYTE all_ones[16];
    BYTE sequential[16];

    memset(all_ones, 0xFF, 16);
    for (int i = 0; i < 16; i++) {
        sequential[i] = i;
    }

    if (!is_weak_key(all_zeros, 16)) {
        printf("All zeros not detected as weak\n");
        return 0;
    }

    if (!is_weak_key(all_ones, 16)) {
        printf("All ones not detected as weak\n");
        return 0;
    }

    if (!is_weak_key(sequential, 16)) {
        printf("Sequential not detected as weak\n");
        return 0;
    }

    BYTE random_key[16];
    if (generate_random_key(random_key) != 1) {
        printf("Random key generation failed\n");
        return 0;
    }

    if (is_weak_key(random_key, 16)) {
        printf("Random key incorrectly detected as weak\n");
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

int run_csprng_unit_tests(void) {
    printf("\nCSPRNG Unit Tests\n");

    int success = 1;

    success &= test_random_bytes_generation();
    success &= test_random_key_generation();
    success &= test_weak_key_detection();

    printf("CSPRNG Unit Tests: %s\n", success ? "PASSED" : "FAILED");
    return success;
}

int main_unit_tests(void) {
    printf("CRYPTOCORE UNIT TEST SUITE\n");

    int all_passed = 1;

    all_passed &= run_csprng_unit_tests();
    all_passed &= run_aes_unit_tests();
    all_passed &= run_sha256_unit_tests();
    all_passed &= run_sha3_256_unit_tests();
    all_passed &= run_hmac_unit_tests();
    all_passed &= run_cmac_unit_tests();
    all_passed &= run_pbkdf2_unit_tests();
    all_passed &= run_hkdf_unit_tests();

    printf("OVERALL RESULT: %s\n", all_passed ? "ALL TESTS PASSED" : "SOME TESTS FAILED");

    return all_passed;
}
