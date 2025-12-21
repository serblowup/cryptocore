/*
 * all_vectors_tests.c
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
#include <stdio.h>
#include <string.h>

static int compare_bytes(const char *test_name, const BYTE *expected,
                        const BYTE *actual, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (expected[i] != actual[i]) {
            printf("%s: FAIL at byte %zu (expected %02x, got %02x)\n",
                   test_name, i, expected[i], actual[i]);
            return 0;
        }
    }
    return 1;
}

static int test_aes_ecb_kat(void) {
    printf("AES ECB Known Answer Tests (NIST SP 800-38A)\n");

    printf("Test 1: ECB-AES128.Encrypt... ");

    BYTE key1[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    BYTE plaintext1[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };

    BYTE expected1[16] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
    };

    BYTE *ciphertext = NULL;
    size_t ciphertext_len;

    if (!ecb_encrypt_no_padding(key1, plaintext1, 16, &ciphertext, &ciphertext_len)) {
        printf("FAIL: Encryption failed\n");
        return 0;
    }

    if (!compare_bytes("ECB Test 1", expected1, ciphertext, 16)) {
        free(ciphertext);
        return 0;
    }

    free(ciphertext);
    printf("[PASS]\n");

    printf("Test 2: ECB-AES128.Decrypt... ");

    BYTE *decrypted = NULL;
    size_t decrypted_len;

    if (!ecb_decrypt(key1, expected1, 16, &decrypted, &decrypted_len)) {
        printf("FAIL: Decryption failed\n");
        return 0;
    }

    if (!compare_bytes("ECB Decrypt Test", plaintext1, decrypted, 16)) {
        free(decrypted);
        return 0;
    }

    free(decrypted);
    printf("[PASS]\n");

    return 1;
}

static int test_aes_cbc_kat(void) {
    printf("AES CBC Known Answer Tests (NIST SP 800-38A)\n");

    printf("Test 1: CBC-AES128.Encrypt... ");

    BYTE key1[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    BYTE iv1[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    BYTE plaintext1[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };

    BYTE expected1[32] = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
        0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2
    };

    BYTE *ciphertext = NULL;
    size_t ciphertext_len;

    if (!cbc_encrypt_no_padding(key1, iv1, plaintext1, 32, &ciphertext, &ciphertext_len)) {
        printf("FAIL: Encryption failed\n");
        return 0;
    }

    if (ciphertext_len != 32) {
        printf("FAIL: Wrong ciphertext length: %zu (expected 32)\n", ciphertext_len);
        free(ciphertext);
        return 0;
    }

    if (!compare_bytes("CBC Test 1", expected1, ciphertext, 32)) {
        free(ciphertext);
        return 0;
    }

    free(ciphertext);
    printf("[PASS]\n");

    printf("Test 2: CBC-AES128.Decrypt... ");

    BYTE *decrypted = NULL;
    size_t decrypted_len;

    if (!cbc_decrypt_no_padding(key1, iv1, expected1, 32, &decrypted, &decrypted_len)) {
        printf("FAIL: Decryption failed\n");
        return 0;
    }

    if (decrypted_len != 32) {
        printf("FAIL: Wrong decrypted length: %zu (expected 32)\n", decrypted_len);
        free(decrypted);
        return 0;
    }

    if (!compare_bytes("CBC Decrypt Test", plaintext1, decrypted, 32)) {
        free(decrypted);
        return 0;
    }

    free(decrypted);
    printf("[PASS]\n");

    return 1;
}

static int test_aes_cfb_kat(void) {
    printf("AES CFB Known Answer Tests (NIST SP 800-38A)\n");

    printf("Test 1: CFB-AES128.Encrypt... ");

    BYTE key1[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    BYTE iv1[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    BYTE plaintext1[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };

    BYTE expected1[32] = {
        0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20,
        0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
        0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f,
        0xcd, 0xe3, 0xcd, 0xad, 0x9f, 0x1c, 0xe5, 0x8b
    };

    BYTE *ciphertext = NULL;
    size_t ciphertext_len;

    if (!cfb_encrypt(key1, iv1, plaintext1, 32, &ciphertext, &ciphertext_len)) {
        printf("FAIL: Encryption failed\n");
        return 0;
    }

    if (ciphertext_len != 32) {
        printf("FAIL: Wrong ciphertext length: %zu\n", ciphertext_len);
        free(ciphertext);
        return 0;
    }

    if (!compare_bytes("CFB Test 1", expected1, ciphertext, 32)) {
        free(ciphertext);
        return 0;
    }

    free(ciphertext);
    printf("[PASS]\n");

    printf("Test 2: CFB-AES128.Decrypt... ");

    BYTE *decrypted = NULL;
    size_t decrypted_len;

    if (!cfb_decrypt(key1, iv1, expected1, 32, &decrypted, &decrypted_len)) {
        printf("FAIL: Decryption failed\n");
        return 0;
    }

    if (!compare_bytes("CFB Decrypt Test", plaintext1, decrypted, 32)) {
        free(decrypted);
        return 0;
    }

    free(decrypted);
    printf("[PASS]\n");

    return 1;
}

static int test_aes_ofb_kat(void) {
    printf("AES OFB Known Answer Tests (NIST SP 800-38A)\n");

    printf("Test 1: OFB-AES128.Encrypt... ");

    BYTE key1[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    BYTE iv1[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    BYTE plaintext1[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };

    BYTE expected1[32] = {
        0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20,
        0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
        0x77, 0x89, 0x50, 0x8d, 0x16, 0x91, 0x8f, 0x03,
        0xf5, 0x3c, 0x52, 0xda, 0xc5, 0x4e, 0xd8, 0x25
    };

    BYTE *ciphertext = NULL;
    size_t ciphertext_len;

    if (!ofb_encrypt_no_padding(key1, iv1, plaintext1, 32, &ciphertext, &ciphertext_len)) {
        printf("FAIL: Encryption failed\n");
        return 0;
    }

    if (ciphertext_len != 32) {
        printf("FAIL: Wrong ciphertext length: %zu (expected 32)\n", ciphertext_len);
        free(ciphertext);
        return 0;
    }

    if (!compare_bytes("OFB Test 1", expected1, ciphertext, 32)) {
        free(ciphertext);
        return 0;
    }

    free(ciphertext);
    printf("[PASS]\n");

    printf("Test 2: OFB-AES128.Decrypt... ");

    BYTE *decrypted = NULL;
    size_t decrypted_len;

    if (!ofb_decrypt_no_padding(key1, iv1, expected1, 32, &decrypted, &decrypted_len)) {
        printf("FAIL: Decryption failed\n");
        return 0;
    }

    if (decrypted_len != 32) {
        printf("FAIL: Wrong decrypted length: %zu (expected 32)\n", decrypted_len);
        free(decrypted);
        return 0;
    }

    if (!compare_bytes("OFB Decrypt Test", plaintext1, decrypted, 32)) {
        free(decrypted);
        return 0;
    }

    free(decrypted);
    printf("[PASS]\n");

    return 1;
}

static int test_aes_ctr_kat(void) {
    printf("AES CTR Known Answer Tests (NIST SP 800-38A)\n");

    printf("Test 1: CTR-AES128.Encrypt... ");

    BYTE key1[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    BYTE iv1[16] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };

    BYTE plaintext1[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };

    BYTE expected1[32] = {
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
        0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
        0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
        0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff
    };

    BYTE *ciphertext = NULL;
    size_t ciphertext_len;

    if (!ctr_encrypt(key1, iv1, plaintext1, 32, &ciphertext, &ciphertext_len)) {
        printf("FAIL: Encryption failed\n");
        return 0;
    }

    if (ciphertext_len != 32) {
        printf("FAIL: Wrong ciphertext length: %zu\n", ciphertext_len);
        free(ciphertext);
        return 0;
    }

    if (!compare_bytes("CTR Test 1", expected1, ciphertext, 32)) {
        free(ciphertext);
        return 0;
    }

    free(ciphertext);
    printf("[PASS]\n");

    printf("Test 2: CTR-AES128.Decrypt... ");

    BYTE *decrypted = NULL;
    size_t decrypted_len;

    if (!ctr_decrypt(key1, iv1, expected1, 32, &decrypted, &decrypted_len)) {
        printf("FAIL: Decryption failed\n");
        return 0;
    }

    if (!compare_bytes("CTR Decrypt Test", plaintext1, decrypted, 32)) {
        free(decrypted);
        return 0;
    }

    free(decrypted);
    printf("[PASS]\n");

    return 1;
}

static int test_sha256_nist_vectors(void) {
    printf("SHA-256 NIST Test Vectors (FIPS 180-4)\n");

    printf("Test 1: SHA-256 empty string... ");

    BYTE empty_data[] = "";
    BYTE expected_empty[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    BYTE digest[32];
    sha256_hash(empty_data, 0, digest);

    if (!compare_bytes("SHA-256 empty", expected_empty, digest, 32)) {
        return 0;
    }
    printf("[PASS]\n");

    printf("Test 2: SHA-256 \"abc\"... ");

    BYTE abc_data[] = "abc";
    BYTE expected_abc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    sha256_hash(abc_data, 3, digest);

    if (!compare_bytes("SHA-256 abc", expected_abc, digest, 32)) {
        return 0;
    }
    printf("PASS\n");

    return 1;
}

static int test_sha3_256_nist_vectors(void) {
    printf("SHA3-256 NIST Test Vectors (FIPS 202)\n");

    printf("Test 1: SHA3-256 empty string... ");

    BYTE empty_data[] = "";
    BYTE expected_empty[32] = {
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
    };

    BYTE digest[32];
    if (!sha3_256_hash(empty_data, 0, digest)) {
        printf("FAIL: Computation failed\n");
        return 0;
    }

    if (!compare_bytes("SHA3-256 empty", expected_empty, digest, 32)) {
        return 0;
    }
    printf("[PASS]\n");

    printf("Test 2: SHA3-256 \"abc\"... ");

    BYTE abc_data[] = "abc";
    BYTE expected_abc[32] = {
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
        0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
        0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
        0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
    };

    if (!sha3_256_hash(abc_data, 3, digest)) {
        printf("FAIL: Computation failed\n");
        return 0;
    }

    if (!compare_bytes("SHA3-256 abc", expected_abc, digest, 32)) {
        return 0;
    }
    printf("[PASS]\n");

    return 1;
}

static int test_hmac_rfc4231_vectors(void) {
    printf("HMAC Test Vectors (RFC 4231)\n");

    printf("Test 1: HMAC-SHA256 Test Case 1... ");

    BYTE key1[20] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b
    };

    BYTE data1[] = "Hi There";
    BYTE expected1[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };

    BYTE digest[32];
    hmac_compute(key1, 20, data1, 8, digest);

    if (!compare_bytes("HMAC Test 1", expected1, digest, 32)) {
        return 0;
    }
    printf("[PASS]\n");

    printf("Test 2: HMAC-SHA256 Test Case 2... ");

    BYTE key2[] = "Jefe";
    BYTE data2[] = "what do ya want for nothing?";
    BYTE expected2[32] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
    };

    hmac_compute(key2, 4, data2, 28, digest);

    if (!compare_bytes("HMAC Test 2", expected2, digest, 32)) {
        return 0;
    }
    printf("[PASS]\n");

    return 1;
}

static int test_pbkdf2_rfc6070_vectors(void) {
    printf("PBKDF2 Test Vectors (RFC 6070)\n");

    printf("Test 1: PBKDF2-HMAC-SHA256 (c=1)... ");

    BYTE password1[] = "password";
    BYTE salt1[] = "salt";
    BYTE expected1[20] = {
        0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
        0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
        0xa8, 0x65, 0x48, 0xc9
    };

    BYTE derived[20];
    if (!pbkdf2_hmac_sha256(password1, 8, salt1, 4, 1, 20, derived)) {
        printf("FAIL: Derivation failed\n");
        return 0;
    }

    if (!compare_bytes("PBKDF2 Test 1", expected1, derived, 20)) {
        return 0;
    }
    printf("[PASS]\n");

    printf("Test 2: PBKDF2-HMAC-SHA256 (c=2)... ");

    BYTE expected2[20] = {
        0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
        0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
        0x2a, 0x30, 0x3f, 0x8e
    };

    if (!pbkdf2_hmac_sha256(password1, 8, salt1, 4, 2, 20, derived)) {
        printf("FAIL: Derivation failed\n");
        return 0;
    }

    if (!compare_bytes("PBKDF2 Test 2", expected2, derived, 20)) {
        return 0;
    }
    printf("[PASS]\n");

    printf("Test 3: PBKDF2-HMAC-SHA256 (c=4096)... ");

    BYTE expected3[20] = {
        0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41,
        0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
        0x96, 0x28, 0x93, 0xa0
    };

    if (!pbkdf2_hmac_sha256(password1, 8, salt1, 4, 4096, 20, derived)) {
        printf("FAIL: Derivation failed\n");
        return 0;
    }

    if (!compare_bytes("PBKDF2 Test 3", expected3, derived, 20)) {
        return 0;
    }
    printf("[PASS]\n");

    return 1;
}

int run_all_vectors_tests(void) {
    printf("\nCRYPTOCORE KNOWN-ANSWER TEST SUITE\n");

    int all_passed = 1;
    int aes_passed = 1;
    int hash_passed = 1;
    int mac_passed = 1;
    int kdf_passed = 1;

    printf("1. AES MODES TESTS (NIST SP 800-38A)\n");
    aes_passed &= test_aes_ecb_kat();
    printf("\n");
    aes_passed &= test_aes_cbc_kat();
    printf("\n");
    aes_passed &= test_aes_cfb_kat();
    printf("\n");
    aes_passed &= test_aes_ofb_kat();
    printf("\n");
    aes_passed &= test_aes_ctr_kat();

    printf("\n2. HASH FUNCTION TESTS\n");
    hash_passed &= test_sha256_nist_vectors();
    printf("\n");
    hash_passed &= test_sha3_256_nist_vectors();

    printf("\n3. MAC FUNCTION TESTS\n");
    mac_passed &= test_hmac_rfc4231_vectors();

    printf("\n4. KEY DERIVATION TESTS\n");
    kdf_passed &= test_pbkdf2_rfc6070_vectors();

    all_passed = aes_passed && hash_passed && mac_passed && kdf_passed;

    printf("\nTEST SUMMARY\n");
    printf("AES Modes Tests:      %s\n", aes_passed ? "PASSED" : "FAILED");
    printf("Hash Function Tests:  %s\n", hash_passed ? "PASSED" : "FAILED");
    printf("MAC Function Tests:   %s\n", mac_passed ? "PASSED" : "FAILED");
    printf("KDF Function Tests:   %s\n", kdf_passed ? "PASSED" : "FAILED");
    printf("OVERALL:              %s\n", all_passed ? "ALL TESTS PASSED" : "SOME TESTS FAILED");

    if (!all_passed) {
        printf("\nDETAILED FAILURE INFORMATION:\n");
        if (!aes_passed) printf("- One or more AES mode tests failed\n");
        if (!hash_passed) printf("- One or more hash function tests failed\n");
        if (!mac_passed) printf("- One or more MAC function tests failed\n");
        if (!kdf_passed) printf("- One or more KDF function tests failed\n");
    }

    return all_passed;
}
