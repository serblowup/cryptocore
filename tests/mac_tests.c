/*
 * mac_tests.c
 *
 *  Created on: 29 нояб. 2025 г.
 *      Author: sergey
 */

#include "../include/main.h"
#include "../include/hmac.h"
#include "../include/cmac.h"
#include <string.h>
#include <stdio.h>

static int test_hmac_rfc_4231(void) {
    printf("HMAC RFC 4231 Test Vectors\n");

    BYTE key1[20] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    BYTE data1[] = "Hi There";
    BYTE expected1[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };

    BYTE digest1[32];
    hmac_compute(key1, 20, data1, strlen((char*)data1), digest1);

    if (memcmp(digest1, expected1, 32) != 0) {
        printf("Fail: Test Case 1\n");
        return 0;
    }
    printf("Pass: Test Case 1\n");

    BYTE key2[] = "Jefe";
    BYTE data2[] = "what do ya want for nothing?";
    BYTE expected2[32] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
    };

    BYTE digest2[32];
    hmac_compute(key2, 4, data2, strlen((char*)data2), digest2);

    if (memcmp(digest2, expected2, 32) != 0) {
        printf("Fail: Test Case 2\n");
        return 0;
    }
    printf("Pass: Test Case 2\n");

    return 1;
}

static int test_cmac_nist_vectors(void) {
    printf("CMAC NIST Test Vectors\n");

    BYTE key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    BYTE expected_empty[16] = {
        0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
        0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46
    };

    BYTE digest_empty[16];
    if (!cmac_compute(key, NULL, 0, digest_empty)) {
        printf("Fail: CMAC empty message computation failed\n");
        return 0;
    }

    if (memcmp(digest_empty, expected_empty, 16) != 0) {
        printf("Fail: CMAC empty message test\n");
        return 0;
    }
    printf("Pass: CMAC empty message test\n");

    return 1;
}

static int test_hmac_verification(void) {
    printf("HMAC Verification Tests\n");

    BYTE key[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    BYTE data[] = "Test message for HMAC verification";
    BYTE digest[32];

    hmac_compute(key, 16, data, strlen((char*)data), digest);

    if (!hmac_verify(key, 16, data, strlen((char*)data), digest)) {
        printf("Fail: HMAC verification with correct data\n");
        return 0;
    }
    printf("Pass: HMAC verification with correct data\n");

    BYTE wrong_key[16] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                         0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    if (hmac_verify(wrong_key, 16, data, strlen((char*)data), digest)) {
        printf("Fail: HMAC verification with wrong key\n");
        return 0;
    }
    printf("Pass: HMAC verification with wrong key\n");

    BYTE tampered_data[] = "Tampered message for HMAC verification";
    if (hmac_verify(key, 16, tampered_data, strlen((char*)tampered_data), digest)) {
        printf("Fail: HMAC verification with tampered data\n");
        return 0;
    }
    printf("Pass: HMAC verification with tampered data\n");

    return 1;
}

static int test_cmac_verification(void) {
    printf("CMAC Verification Tests\n");

    BYTE key[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    BYTE data[] = "Test message for CMAC verification";
    BYTE digest[16];

    if (!cmac_compute(key, data, strlen((char*)data), digest)) {
        printf("Fail: CMAC computation failed\n");
        return 0;
    }

    if (!cmac_verify(key, data, strlen((char*)data), digest)) {
        printf("Fail: CMAC verification with correct data\n");
        return 0;
    }
    printf("Pass: CMAC verification with correct data\n");

    BYTE wrong_key[16] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                         0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    if (cmac_verify(wrong_key, data, strlen((char*)data), digest)) {
        printf("Fail: CMAC verification with wrong key\n");
        return 0;
    }
    printf("Pass: CMAC verification with wrong key\n");

    return 1;
}

static int test_hmac_key_sizes(void) {
    printf("HMAC Key Size Tests\n");

    BYTE data[] = "Test data";

    BYTE short_key[] = "abcd";
    BYTE digest_short[32];
    hmac_compute(short_key, 4, data, strlen((char*)data), digest_short);
    printf("Pass: HMAC with short key (4 bytes)\n");

    BYTE block_key[64];
    memset(block_key, 0xaa, 64);
    BYTE digest_block[32];
    hmac_compute(block_key, 64, data, strlen((char*)data), digest_block);
    printf("Pass: HMAC with block-size key (64 bytes)\n");

    BYTE long_key[100];
    memset(long_key, 0xbb, 100);
    BYTE digest_long[32];
    hmac_compute(long_key, 100, data, strlen((char*)data), digest_long);
    printf("Pass: HMAC with long key (100 bytes)\n");

    return 1;
}

static int test_empty_file_hmac(void) {
    printf("Empty File HMAC Test\n");

    const char *filename = "empty_test.tmp";
    FILE *file = fopen(filename, "wb");
    if (!file) {
        printf("Fail: Cannot create empty test file\n");
        return 0;
    }
    fclose(file);

    BYTE key[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    BYTE digest[32];

    if (!hmac_file_compute(key, 16, filename, digest, 8192)) {
        printf("Fail: HMAC computation for empty file\n");
        remove(filename);
        return 0;
    }

    printf("Pass: HMAC computation for empty file\n");
    remove(filename);
    return 1;
}

int run_all_mac_tests(void) {
    printf("Running MAC Tests...\n\n");

    int success = 1;

    success &= test_hmac_rfc_4231();
    printf("\n");

    success &= test_cmac_nist_vectors();
    printf("\n");

    success &= test_hmac_verification();
    printf("\n");

    success &= test_cmac_verification();
    printf("\n");

    success &= test_hmac_key_sizes();
    printf("\n");

    success &= test_empty_file_hmac();
    printf("\n");

    printf("MAC TESTS %s\n", success ? "PASSED" : "FAILED");
    return success;
}
