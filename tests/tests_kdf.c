/*
 * tests_kdf.c
 *
 *  Created on: 20 дек. 2025 г.
 *      Author: sergey
 */

#include "../include/main.h"
#include "../include/pbkdf2.h"
#include "../include/hkdf.h"
#include <stdio.h>
#include <string.h>

static int test_pbkdf2_vector_1(void) {
    printf("Test PBKDF2 Vector 1 (SHA256, c=1)... ");

    BYTE password[] = "password";
    BYTE salt[] = "salt";
    BYTE expected[20] = {
        0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
        0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
        0xa8, 0x65, 0x48, 0xc9
    };

    BYTE derived[20];
    if (!pbkdf2_hmac_sha256(password, 8, salt, 4, 1, 20, derived)) {
        printf("Computation failed\n");
        return 0;
    }

    if (memcmp(derived, expected, 20) != 0) {
        printf("Result mismatch\n");
        return 0;
    }

    printf("OK\n");
    return 1;
}

static int test_pbkdf2_vector_2(void) {
    printf("Test PBKDF2 Vector 2 (SHA256, c=2)... ");

    BYTE password[] = "password";
    BYTE salt[] = "salt";
    BYTE expected[20] = {
        0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
        0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
        0x2a, 0x30, 0x3f, 0x8e
    };

    BYTE derived[20];
    if (!pbkdf2_hmac_sha256(password, 8, salt, 4, 2, 20, derived)) {
        printf("Computation failed\n");
        return 0;
    }

    if (memcmp(derived, expected, 20) != 0) {
        printf("Result mismatch\n");
        return 0;
    }

    printf("OK\n");
    return 1;
}

static int test_pbkdf2_vector_3(void) {
    printf("Test PBKDF2 Vector 3 (SHA256, c=4096)... ");

    BYTE password[] = "password";
    BYTE salt[] = "salt";
    BYTE expected[20] = {
        0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41,
        0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
        0x96, 0x28, 0x93, 0xa0
    };

    BYTE derived[20];
    if (!pbkdf2_hmac_sha256(password, 8, salt, 4, 4096, 20, derived)) {
        printf("Computation failed\n");
        return 0;
    }

    if (memcmp(derived, expected, 20) != 0) {
        printf("Result mismatch\n");
        return 0;
    }

    printf("OK\n");
    return 1;
}

static int test_pbkdf2_long_password_salt(void) {
    printf("Test PBKDF2 Long Password/Salt (c=4096, dklen=25)... ");

    BYTE password[] = "passwordPASSWORDpassword";
    BYTE salt[] = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
    BYTE expected[25] = {
        0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f,
        0x32, 0xd8, 0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf,
        0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18,
        0x1c
    };

    BYTE derived[25];
    if (!pbkdf2_hmac_sha256(password, 24, salt, 36, 4096, 25, derived)) {
        printf("Computation failed\n");
        return 0;
    }

    if (memcmp(derived, expected, 25) != 0) {
        printf("Result mismatch\n");
        return 0;
    }

    printf("OK\n");
    return 1;
}

static int test_pbkdf2_binary_data(void) {
    printf("Test PBKDF2 Binary Data (NULL bytes)... ");

    BYTE password[] = {'p', 'a', 's', 's', 0x00, 'w', 'o', 'r', 'd'};
    BYTE salt[] = {'s', 'a', 0x00, 'l', 't'};
    BYTE expected[16] = {
        0x89, 0xb6, 0x9d, 0x05, 0x16, 0xf8, 0x29, 0x89,
        0x3c, 0x69, 0x62, 0x26, 0x65, 0x0a, 0x86, 0x87
    };

    BYTE derived[16];
    if (!pbkdf2_hmac_sha256(password, 9, salt, 5, 4096, 16, derived)) {
        printf("Computation failed\n");
        return 0;
    }

    if (memcmp(derived, expected, 16) != 0) {
        printf("Result mismatch\n");
        return 0;
    }

    printf("OK\n");
    return 1;
}

static int test_pbkdf2_different_lengths(void) {
    printf("Test PBKDF2 Different Key Lengths... ");

    BYTE password[] = "password";
    BYTE salt[] = "salt";
    int passed = 1;

    for (size_t len = 1; len <= 100; len += 13) {
        BYTE derived[100];
        if (!pbkdf2_hmac_sha256(password, 8, salt, 4, 1000, len, derived)) {
            printf("Failed for length %zu\n", len);
            passed = 0;
            break;
        }

        int all_zero = 1;
        for (size_t i = 0; i < len; i++) {
            if (derived[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (all_zero) {
            printf("Zero key for length %zu\n", len);
            passed = 0;
            break;
        }
    }

    if (passed) printf("OK\n");
    return passed;
}

static int test_pbkdf2_iteration_consistency(void) {
    printf("Test PBKDF2 Iteration Consistency... ");

    BYTE password[] = "test123";
    BYTE salt[] = "randsalt";
    BYTE derived1[32];
    BYTE derived2[32];

    if (!pbkdf2_hmac_sha256(password, 7, salt, 8, 10000, 32, derived1)) {
        printf("First computation failed\n");
        return 0;
    }

    if (!pbkdf2_hmac_sha256(password, 7, salt, 8, 10000, 32, derived2)) {
        printf("Second computation failed\n");
        return 0;
    }

    if (memcmp(derived1, derived2, 32) != 0) {
        printf("Results not consistent\n");
        return 0;
    }

    printf("OK\n");
    return 1;
}

static int test_hkdf_basic(void) {
    printf("Test HKDF Basic... ");

    BYTE master_key[32];
    memset(master_key, 0xAA, 32);

    BYTE derived1[32];
    BYTE derived2[32];

    if (!derive_key_from_master(master_key, 32, "encryption", 32, derived1)) {
        printf("First derivation failed\n");
        return 0;
    }

    if (!derive_key_from_master(master_key, 32, "encryption", 32, derived2)) {
        printf("Second derivation failed\n");
        return 0;
    }

    if (memcmp(derived1, derived2, 32) != 0) {
        printf("Results not deterministic\n");
        return 0;
    }

    printf("OK\n");
    return 1;
}

static int test_hkdf_context_separation(void) {
    printf("Test HKDF Context Separation... ");

    BYTE master_key[32];
    memset(master_key, 0xBB, 32);

    BYTE key1[32];
    BYTE key2[32];

    if (!derive_key_from_master(master_key, 32, "encryption", 32, key1)) {
        printf("First derivation failed\n");
        return 0;
    }

    if (!derive_key_from_master(master_key, 32, "authentication", 32, key2)) {
        printf("Second derivation failed\n");
        return 0;
    }

    if (memcmp(key1, key2, 32) == 0) {
        printf("Different contexts gave same key\n");
        return 0;
    }

    printf("OK\n");
    return 1;
}

static int test_hkdf_different_lengths(void) {
    printf("Test HKDF Different Lengths... ");

    BYTE master_key[32];
    memset(master_key, 0xCC, 32);

    int passed = 1;
    for (size_t len = 1; len <= 128; len += 17) {
        BYTE derived[128];
        if (!derive_key_from_master(master_key, 32, "test", len, derived)) {
            printf("Failed for length %zu\n", len);
            passed = 0;
            break;
        }

        int all_zero = 1;
        for (size_t i = 0; i < len; i++) {
            if (derived[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (all_zero) {
            printf("Zero key for length %zu\n", len);
            passed = 0;
            break;
        }
    }

    if (passed) printf("OK\n");
    return passed;
}

static int test_salt_randomness(void) {
    printf("Test Salt Randomness... ");

    BYTE salts[10000][16];
    int duplicates = 0;

    for (int i = 0; i < 10000; i++) {
        if (generate_random_bytes(salts[i], 16) != 1) {
            printf("Failed to generate salt %d\n", i);
            return 0;
        }
    }

    for (int i = 0; i < 9999; i++) {
        for (int j = i + 1; j < 10000; j++) {
            if (memcmp(salts[i], salts[j], 16) == 0) {
                duplicates++;
            }
        }
    }

    if (duplicates > 0) {
        printf("Found %d duplicate salts\n", duplicates);
        return 0;
    }

    printf("OK (no duplicates in 10000 salts)\n");
    return 1;
}

static int test_pbkdf2_performance(void) {
    printf("Test PBKDF2 Performance... ");

    BYTE password[] = "benchmark";
    BYTE salt[16] = "benchmark_salt";
    BYTE derived[32];

    clock_t start = clock();
    if (!pbkdf2_hmac_sha256(password, 9, salt, 16, 10000, 32, derived)) {
        printf("Failed 10k iterations\n");
        return 0;
    }
    clock_t end = clock();
    double time_10k = (double)(end - start) / CLOCKS_PER_SEC;

    start = clock();
    if (!pbkdf2_hmac_sha256(password, 9, salt, 16, 100000, 32, derived)) {
        printf("Failed 100k iterations\n");
        return 0;
    }
    end = clock();
    double time_100k = (double)(end - start) / CLOCKS_PER_SEC;

    start = clock();
    if (!pbkdf2_hmac_sha256(password, 9, salt, 16, 1000000, 32, derived)) {
        printf("Failed 1M iterations\n");
        return 0;
    }
    end = clock();
    double time_1M = (double)(end - start) / CLOCKS_PER_SEC;

    start = clock();
    if (!pbkdf2_hmac_sha256(password, 9, salt, 16, 2000000, 32, derived)) {
        printf("Failed 2M iterations\n");
        return 0;
    }
    end = clock();
    double time_2M = (double)(end - start) / CLOCKS_PER_SEC;

    printf("OK (10k: %.3fs, 100k: %.3fs, 1M: %.3fs, 2M: %.3fs)\n",
           time_10k, time_100k, time_1M, time_2M);
    return 1;
}

int run_all_kdf_tests(void) {
    printf("\nRUNNING KDF TESTS\n");

    int success = 1;

    printf("PBKDF2 Test Vectors:\n");
    success &= test_pbkdf2_vector_1();
    success &= test_pbkdf2_vector_2();
    success &= test_pbkdf2_vector_3();
    success &= test_pbkdf2_long_password_salt();
    success &= test_pbkdf2_binary_data();

    printf("\nPBKDF2 Functional Tests:\n");
    success &= test_pbkdf2_different_lengths();
    success &= test_pbkdf2_iteration_consistency();

    printf("\nHKDF Tests:\n");
    success &= test_hkdf_basic();
    success &= test_hkdf_context_separation();
    success &= test_hkdf_different_lengths();

    printf("\nSecurity Tests:\n");
    success &= test_salt_randomness();

    printf("\nPerformance Tests:\n");
    success &= test_pbkdf2_performance();

    printf("\nKDF TESTS %s\n", success ? "PASSED" : "FAILED");
    return success;
}
