#include "../include/main.h"
#include <stdio.h>
#include <string.h>

int test_key_uniqueness(void) {
    const int num_keys = 1000;
    BYTE keys[num_keys][AES_128_KEY_SIZE];

    printf("Key Uniqueness Test\n");
    printf("Generating %d random keys...\n", num_keys);

    for (int i = 0; i < num_keys; i++) {
        if (generate_random_key(keys[i]) != 1) {
            fprintf(stderr, "Error: Failed to generate key %d\n", i);
            return 0;
        }
    }

    for (int i = 0; i < num_keys; i++) {
        for (int j = i + 1; j < num_keys; j++) {
            if (memcmp(keys[i], keys[j], AES_128_KEY_SIZE) == 0) {
                fprintf(stderr, "Fail: Duplicate keys found at indices %d and %d\n", i, j);
                fprintf(stderr, "Duplicate key: ");
                for (int k = 0; k < AES_128_KEY_SIZE; k++) {
                    fprintf(stderr, "%02x", keys[i][k]);
                }
                fprintf(stderr, "\n");
                return 0;
            }
        }
    }

    printf("Success: All %d keys are unique\n", num_keys);
    return 1;
}

int test_bit_distribution(void) {
    const int num_samples = 10000;
    int ones_count = 0;
    int total_bits = 0;

    printf("Bit Distribution Test\n");
    printf("Testing %d random bytes...\n", num_samples);

    BYTE random_bytes[num_samples];
    if (generate_random_bytes(random_bytes, num_samples) != 1) {
        fprintf(stderr, "Error: Failed to generate random bytes\n");
        return 0;
    }

    for (int i = 0; i < num_samples; i++) {
        for (int bit = 0; bit < 8; bit++) {
            if (random_bytes[i] & (1 << bit)) {
                ones_count++;
            }
            total_bits++;
        }
    }

    double ones_ratio = (double)ones_count / total_bits;
    printf("Ones: %d, Zeros: %d, Total bits: %d\n", ones_count, total_bits - ones_count, total_bits);
    printf("Ones ratio: %.4f (ideal: 0.5000)\n", ones_ratio);

    if (ones_ratio > 0.45 && ones_ratio < 0.55) {
        printf("Success: Bit distribution is good\n");
        return 1;
    } else {
        printf("Fail: Bit distribution is skewed\n");
        return 0;
    }
}


int test_weak_key_detection(void) {
    printf("Weak Key Detection Test\n");

    BYTE weak_keys[][AES_128_KEY_SIZE] = {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // все нули
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, // все единицы
        {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}, // последовательные
    };

    int num_weak_keys = sizeof(weak_keys) / sizeof(weak_keys[0]);
    int all_detected = 1;

    for (int i = 0; i < num_weak_keys; i++) {
        if (!is_weak_key(weak_keys[i], AES_128_KEY_SIZE)) {
            printf("Fail: Weak key %d not detected\n", i);
            all_detected = 0;
        } else {
            printf("Weak key %d correctly detected\n", i);
        }
    }

    BYTE good_key[AES_128_KEY_SIZE];
    if (generate_random_key(good_key) == 1) {
        if (is_weak_key(good_key, AES_128_KEY_SIZE)) {
            printf("Fail: Good key incorrectly detected as weak\n");
            all_detected = 0;
        } else {
            printf("Good key correctly not detected as weak\n");
        }
    }

    return all_detected;
}

int run_all_key_tests(void) {
    printf("Running CSPRNG Key Tests...\n\n");

    int success = 1;

    success &= test_key_uniqueness();
    printf("\n");

    success &= test_bit_distribution();
    printf("\n");

    success &= test_weak_key_detection();
    printf("\n");

    if (success) {
        printf("ALL KEY TESTS PASSED!\n");
    } else {
        printf("SOME KEY TESTS FAILED!\n");
    }

    return success;
}
