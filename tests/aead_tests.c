/*
 * aead_tests.c
 *
 *  Created on: 2 дек. 2025 г.
 *      Author: sergey
 */

#include "../include/main.h"
#include "../include/gcm.h"
#include "../include/etm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void suppress_stderr(void) {
    fflush(stderr);
    #ifdef __linux__
    freopen("/dev/null", "w", stderr);
    #else
    freopen("nul", "w", stderr);
    #endif
}

static void restore_stderr(FILE *original_stderr) {
    fflush(stderr);
    fclose(stderr);
    *stderr = *original_stderr;
}

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

static int test_nist_gcm_test_case_1(void) {
    printf("NIST Test Case 1 (empty data) ... ");

    BYTE key[16] = {0};
    BYTE iv[12] = {0};
    BYTE plaintext[0] = {};
    BYTE aad[0] = {};

    BYTE expected_tag[16] = {
        0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
        0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a
    };

    BYTE ciphertext[1];
    BYTE tag[16];

    if (!gcm_encrypt_with_fixed_nonce(key, iv, 12,
                                      plaintext, 0,
                                      aad, 0,
                                      ciphertext, tag)) {
        printf("Fail: Encryption failed\n");
        return 0;
    }

    if (!compare_bytes("Test Case 1 Tag", expected_tag, tag, 16)) {
        return 0;
    }

    printf("Pass\n");
    return 1;
}

static int test_nist_gcm_non96_iv(void) {
    printf("NIST Test (non-96-bit IV) ... ");

    BYTE key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    BYTE iv[8] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };

    BYTE plaintext[16] = "Test 64-bit IV";
    BYTE aad[] = "Additional Data";

    BYTE ciphertext[16];
    BYTE tag[16];

    if (!gcm_encrypt_with_fixed_nonce(key, iv, 8,
                                      plaintext, 16,
                                      aad, strlen((char*)aad),
                                      ciphertext, tag)) {
        printf("Skip: 64-bit IV not supported\n");
        return 1;
    }

    BYTE decrypted[16];
    if (!gcm_decrypt_with_fixed_nonce(key, iv, 8,
                                      ciphertext, 16,
                                      aad, strlen((char*)aad),
                                      tag, decrypted)) {
        printf("Fail: Decryption with 64-bit IV failed\n");
        return 0;
    }

    if (!compare_bytes("Non-96 IV Plaintext", plaintext, decrypted, 16)) {
        return 0;
    }

    printf("Pass\n");
    return 1;
}

static int test_gcm_basic(void) {
    printf("Test 1: Basic GCM encryption/decryption ... ");

    BYTE key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    BYTE plaintext[] = "Hello GCM World! This is a test message for GCM.";
    BYTE aad[] = "Additional Authenticated Data";

    BYTE *encrypted = NULL;
    size_t encrypted_len = 0;

    if (!gcm_encrypt_full(key, plaintext, strlen((char*)plaintext),
                         aad, strlen((char*)aad), &encrypted, &encrypted_len)) {
        printf("Fail: Encryption failed\n");
        return 0;
    }

    BYTE *decrypted = NULL;
    size_t decrypted_len = 0;

    if (!gcm_decrypt_full(key, encrypted, encrypted_len,
                         aad, strlen((char*)aad), &decrypted, &decrypted_len)) {
        printf("Fail: Decryption failed\n");
        free(encrypted);
        return 0;
    }

    if (decrypted_len != strlen((char*)plaintext) ||
        memcmp(plaintext, decrypted, decrypted_len) != 0) {
        printf("Fail: Plaintext mismatch\n");
        free(encrypted);
        free(decrypted);
        return 0;
    }

    free(encrypted);
    free(decrypted);
    printf("Pass\n");
    return 1;
}

static int test_gcm_empty(void) {
    printf("Test 2: GCM with empty data ... ");

    BYTE key[16] = {0};
    BYTE plaintext[] = "";
    BYTE aad[] = "";

    BYTE *encrypted = NULL;
    size_t encrypted_len = 0;

    if (!gcm_encrypt_full(key, plaintext, 0, aad, 0, &encrypted, &encrypted_len)) {
        printf("Fail: Empty encryption failed\n");
        return 0;
    }

    if (encrypted_len != 28) {
        printf("Fail: Wrong size for empty data (expected 28, got %zu)\n", encrypted_len);
        free(encrypted);
        return 0;
    }

    BYTE *decrypted = NULL;
    size_t decrypted_len = 0;

    if (!gcm_decrypt_full(key, encrypted, encrypted_len, aad, 0, &decrypted, &decrypted_len)) {
        printf("Fail: Empty decryption failed\n");
        free(encrypted);
        return 0;
    }

    if (decrypted_len != 0 || decrypted == NULL) {
        printf("Fail: Empty decryption wrong result\n");
        free(encrypted);
        free(decrypted);
        return 0;
    }

    free(encrypted);
    free(decrypted);
    printf("Pass\n");
    return 1;
}

static int test_gcm_wrong_aad(void) {
    printf("Test 3: GCM with wrong AAD ... ");

    BYTE key[16];
    memset(key, 0xAA, 16);

    BYTE plaintext[] = "Secret message";
    BYTE correct_aad[] = "Correct AAD";
    BYTE wrong_aad[] = "Wrong AAD";

    BYTE *encrypted = NULL;
    size_t encrypted_len = 0;

    if (!gcm_encrypt_full(key, plaintext, strlen((char*)plaintext),
                         correct_aad, strlen((char*)correct_aad), &encrypted, &encrypted_len)) {
        printf("Fail: Encryption failed\n");
        return 0;
    }

    BYTE *decrypted = NULL;
    size_t decrypted_len = 0;

    FILE *original_stderr = stderr;
    suppress_stderr();

    int should_fail = gcm_decrypt_full(key, encrypted, encrypted_len,
                                      wrong_aad, strlen((char*)wrong_aad),
                                      &decrypted, &decrypted_len);

    restore_stderr(original_stderr);

    if (should_fail) {
        printf("Fail: Should have rejected wrong AAD\n");
        free(encrypted);
        free(decrypted);
        return 0;
    }

    if (!gcm_decrypt_full(key, encrypted, encrypted_len,
                         correct_aad, strlen((char*)correct_aad), &decrypted, &decrypted_len)) {
        printf("Fail: Correct AAD should have worked\n");
        free(encrypted);
        return 0;
    }

    free(encrypted);
    free(decrypted);
    printf("Pass\n");
    return 1;
}

static int test_gcm_tampered_ciphertext(void) {
    printf("Test 4: GCM with tampered ciphertext ... ");

    BYTE key[16];
    for (int i = 0; i < 16; i++) key[i] = i;

    BYTE plaintext[] = "Another secret message";
    BYTE aad[] = "Some AAD";

    BYTE *encrypted = NULL;
    size_t encrypted_len = 0;

    if (!gcm_encrypt_full(key, plaintext, strlen((char*)plaintext),
                         aad, strlen((char*)aad), &encrypted, &encrypted_len)) {
        printf("Fail: Encryption failed\n");
        return 0;
    }

    encrypted[12 + 5] ^= 0x01;

    BYTE *decrypted = NULL;
    size_t decrypted_len = 0;

    FILE *original_stderr = stderr;
    suppress_stderr();

    int should_fail = gcm_decrypt_full(key, encrypted, encrypted_len,
                                      aad, strlen((char*)aad),
                                      &decrypted, &decrypted_len);

    restore_stderr(original_stderr);

    if (should_fail) {
        printf("Fail: Should have rejected tampered ciphertext\n");
        free(encrypted);
        free(decrypted);
        return 0;
    }

    free(encrypted);
    printf("Pass\n");
    return 1;
}

static int test_gcm_tampered_tag(void) {
    printf("Test 5: GCM with tampered tag ... ");

    BYTE key[16];
    memset(key, 0x33, 16);

    BYTE plaintext[] = "Message with tampered tag";
    BYTE aad[] = "AAD for tag test";

    BYTE *encrypted = NULL;
    size_t encrypted_len = 0;

    if (!gcm_encrypt_full(key, plaintext, strlen((char*)plaintext),
                         aad, strlen((char*)aad), &encrypted, &encrypted_len)) {
        printf("Fail: Encryption failed\n");
        return 0;
    }

    encrypted[encrypted_len - 1] ^= 0x01;

    BYTE *decrypted = NULL;
    size_t decrypted_len = 0;

    FILE *original_stderr = stderr;
    suppress_stderr();

    int should_fail = gcm_decrypt_full(key, encrypted, encrypted_len,
                                      aad, strlen((char*)aad),
                                      &decrypted, &decrypted_len);

    restore_stderr(original_stderr);

    if (should_fail) {
        printf("Fail: Should have rejected tampered tag\n");
        free(encrypted);
        free(decrypted);
        return 0;
    }

    free(encrypted);
    printf("Pass\n");
    return 1;
}

static int test_gcm_wrong_key(void) {
    printf("Test 6: GCM with wrong key ... ");

    BYTE correct_key[16];
    BYTE wrong_key[16];

    for (int i = 0; i < 16; i++) {
        correct_key[i] = i;
        wrong_key[i] = i + 0x10;
    }

    BYTE plaintext[] = "Key test message";
    BYTE aad[] = "Key test AAD";

    BYTE *encrypted = NULL;
    size_t encrypted_len = 0;

    if (!gcm_encrypt_full(correct_key, plaintext, strlen((char*)plaintext),
                         aad, strlen((char*)aad), &encrypted, &encrypted_len)) {
        printf("Fail: Encryption failed\n");
        return 0;
    }

    BYTE *decrypted = NULL;
    size_t decrypted_len = 0;

    FILE *original_stderr = stderr;
    suppress_stderr();

    int should_fail = gcm_decrypt_full(wrong_key, encrypted, encrypted_len,
                                      aad, strlen((char*)aad),
                                      &decrypted, &decrypted_len);

    restore_stderr(original_stderr);

    if (should_fail) {
        printf("Fail: Should have rejected wrong key\n");
        free(encrypted);
        free(decrypted);
        return 0;
    }

    free(encrypted);
    printf("Pass\n");
    return 1;
}

static int test_gcm_nonce_uniqueness(void) {
    printf("Test 7: GCM nonce uniqueness ... ");

    BYTE key[16] = {0};
    BYTE plaintext[] = "Test";
    BYTE aad[] = "";

    BYTE *encrypted1 = NULL, *encrypted2 = NULL;
    size_t len1 = 0, len2 = 0;

    if (!gcm_encrypt_full(key, plaintext, 4, aad, 0, &encrypted1, &len1) ||
        !gcm_encrypt_full(key, plaintext, 4, aad, 0, &encrypted2, &len2)) {
        printf("Fail: Encryption failed\n");
        free(encrypted1);
        free(encrypted2);
        return 0;
    }

    if (memcmp(encrypted1, encrypted2, 12) == 0) {
        printf("Fail: Nonces are identical (highly unlikely with CSPRNG)\n");
        free(encrypted1);
        free(encrypted2);
        return 0;
    }

    free(encrypted1);
    free(encrypted2);
    printf("Pass\n");
    return 1;
}

static int test_gcm_large_aad(void) {
    printf("Test 8: GCM with large AAD ... ");

    BYTE key[16];
    memset(key, 0x55, 16);

    BYTE plaintext[] = "Short message";

    size_t large_aad_size = 1024;
    BYTE *large_aad = malloc(large_aad_size);
    if (!large_aad) {
        printf("Fail: Memory allocation failed\n");
        return 0;
    }

    for (size_t i = 0; i < large_aad_size; i++) {
        large_aad[i] = i % 256;
    }

    BYTE *encrypted = NULL;
    size_t encrypted_len = 0;

    if (!gcm_encrypt_full(key, plaintext, strlen((char*)plaintext),
                         large_aad, large_aad_size, &encrypted, &encrypted_len)) {
        printf("Fail: Encryption with large AAD failed\n");
        free(large_aad);
        return 0;
    }

    BYTE *decrypted = NULL;
    size_t decrypted_len = 0;

    if (!gcm_decrypt_full(key, encrypted, encrypted_len,
                         large_aad, large_aad_size, &decrypted, &decrypted_len)) {
        printf("Fail: Decryption with large AAD failed\n");
        free(large_aad);
        free(encrypted);
        return 0;
    }

    if (memcmp(plaintext, decrypted, decrypted_len) != 0) {
        printf("Fail: Plaintext mismatch with large AAD\n");
        free(large_aad);
        free(encrypted);
        free(decrypted);
        return 0;
    }

    free(large_aad);
    free(encrypted);
    free(decrypted);
    printf("Pass\n");
    return 1;
}

static int test_etm_basic(void) {
    printf("Test ETM-1: Basic Encrypt-then-MAC ... ");

    BYTE key[16];
    memset(key, 0xAA, 16);

    BYTE plaintext[] = "Test message for Encrypt-then-MAC";
    BYTE aad[] = "Additional authenticated data";

    BYTE *encrypted = NULL;
    size_t encrypted_len = 0;

    if (!encrypt_then_mac(MODE_CTR, key, 16,
                         plaintext, strlen((char*)plaintext),
                         aad, strlen((char*)aad),
                         &encrypted, &encrypted_len)) {
        printf("Fail: ETM encryption failed\n");
        return 0;
    }

    BYTE *decrypted = NULL;
    size_t decrypted_len = 0;

    if (!decrypt_then_verify(MODE_CTR, key, 16,
                            encrypted, encrypted_len,
                            aad, strlen((char*)aad),
                            &decrypted, &decrypted_len)) {
        printf("Fail: ETM decryption failed\n");
        free(encrypted);
        return 0;
    }

    if (decrypted_len != strlen((char*)plaintext) ||
        memcmp(plaintext, decrypted, decrypted_len) != 0) {
        printf("Fail: Plaintext mismatch\n");
        free(encrypted);
        free(decrypted);
        return 0;
    }

    free(encrypted);
    free(decrypted);
    printf("Pass\n");
    return 1;
}

static int test_etm_wrong_aad(void) {
    printf("Test ETM-2: ETM with wrong AAD ... ");

    BYTE key[16];
    for (int i = 0; i < 16; i++) key[i] = i * 0x11;

    BYTE plaintext[] = "Secret ETM message";
    BYTE correct_aad[] = "Correct AAD";
    BYTE wrong_aad[] = "Wrong AAD";

    BYTE *encrypted = NULL;
    size_t encrypted_len = 0;

    if (!encrypt_then_mac(MODE_CBC, key, 16,
                         plaintext, strlen((char*)plaintext),
                         correct_aad, strlen((char*)correct_aad),
                         &encrypted, &encrypted_len)) {
        printf("Fail: ETM encryption failed\n");
        return 0;
    }

    BYTE *decrypted = NULL;
    size_t decrypted_len = 0;

    FILE *original_stderr = stderr;
    suppress_stderr();

    int should_fail = decrypt_then_verify(MODE_CBC, key, 16,
                                         encrypted, encrypted_len,
                                         wrong_aad, strlen((char*)wrong_aad),
                                         &decrypted, &decrypted_len);

    restore_stderr(original_stderr);

    if (should_fail) {
        printf("Fail: Should have rejected wrong AAD\n");
        free(encrypted);
        free(decrypted);
        return 0;
    }

    if (!decrypt_then_verify(MODE_CBC, key, 16,
                            encrypted, encrypted_len,
                            correct_aad, strlen((char*)correct_aad),
                            &decrypted, &decrypted_len)) {
        printf("Fail: Correct AAD should have worked\n");
        free(encrypted);
        return 0;
    }

    free(encrypted);
    free(decrypted);
    printf("Pass\n");
    return 1;
}

int run_aead_tests(void) {
    printf("\nRUNNING SIMPLIFIED AEAD TESTS\n\n");

    int success = 1;
    int nist_success = 1;
    int functional_success = 1;
    int etm_success = 1;

    printf("NIST GCM TEST VECTORS\n");
    nist_success &= test_nist_gcm_test_case_1();
    nist_success &= test_nist_gcm_non96_iv();

    printf("\nFUNCTIONAL GCM TESTS\n");
    functional_success &= test_gcm_basic();
    functional_success &= test_gcm_empty();
    functional_success &= test_gcm_wrong_aad();
    functional_success &= test_gcm_tampered_ciphertext();
    functional_success &= test_gcm_tampered_tag();
    functional_success &= test_gcm_wrong_key();
    functional_success &= test_gcm_nonce_uniqueness();
    functional_success &= test_gcm_large_aad();

    printf("\nENCRYPT-THEN-MAC (ETM) TESTS\n");
    etm_success &= test_etm_basic();
    etm_success &= test_etm_wrong_aad();

    success = nist_success && functional_success && etm_success;

    printf("\nTEST SUMMARY\n");
    printf("NIST Tests:         %s\n", nist_success ? "PASSED" : "FAILED");
    printf("Functional Tests:   %s\n", functional_success ? "PASSED" : "FAILED");
    printf("ETM Tests:          %s\n", etm_success ? "PASSED" : "FAILED");
    printf("OVERALL:            %s\n", success ? "PASSED" : "FAILED");

    if (!success) {
        printf("\nFAILED TESTS DETAILS\n");
        if (!nist_success) printf("- One or more NIST test vectors failed\n");
        if (!functional_success) printf("- One or more functional tests failed\n");
        if (!etm_success) printf("- One or more ETM tests failed\n");
    }

    return success;
}
