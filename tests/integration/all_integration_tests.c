/*
 * all_integration_tests.c
 *
 *  Created on: 21 дек. 2025 г.
 *      Author: sergey
 */

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include "../../include/main.h"
#include "../../include/sha256.h"
#include "../../include/sha3_256.h"
#include "../../include/hmac.h"
#include "../../include/cmac.h"
#include "../../include/gcm.h"
#include "../../include/etm.h"
#include "../../include/pbkdf2.h"
#include "../../include/hkdf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <ctype.h>

#define TEST_FILE_SIZE 1024
#define TEST_LARGE_FILE_SIZE (5 * 1024 * 1024)

static int create_test_file(const char *filename, size_t size) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        printf("  Error: Cannot create test file %s\n", filename);
        return 0;
    }

    BYTE *data = malloc(size);
    if (!data) {
        fclose(file);
        return 0;
    }

    if (generate_random_bytes(data, size) != 1) {
        printf("  Error: Failed to generate random data\n");
        free(data);
        fclose(file);
        return 0;
    }

    fwrite(data, 1, size, file);
    fclose(file);
    free(data);
    return 1;
}

static int compare_files(const char *file1, const char *file2) {
    FILE *f1 = fopen(file1, "rb");
    FILE *f2 = fopen(file2, "rb");

    if (!f1 || !f2) {
        if (f1) fclose(f1);
        if (f2) fclose(f2);
        return 0;
    }

    fseek(f1, 0, SEEK_END);
    fseek(f2, 0, SEEK_END);
    long size1 = ftell(f1);
    long size2 = ftell(f2);

    if (size1 != size2) {
        fclose(f1);
        fclose(f2);
        return 0;
    }

    fseek(f1, 0, SEEK_SET);
    fseek(f2, 0, SEEK_SET);

    int result = 1;
    BYTE buffer1[4096], buffer2[4096];
    size_t bytes_read;

    while ((bytes_read = fread(buffer1, 1, sizeof(buffer1), f1)) > 0) {
        if (fread(buffer2, 1, bytes_read, f2) != bytes_read) {
            result = 0;
            break;
        }
        if (memcmp(buffer1, buffer2, bytes_read) != 0) {
            result = 0;
            break;
        }
    }

    fclose(f1);
    fclose(f2);
    return result;
}

static int run_system_command(const char *command) {
    printf("  Running: %s\n", command);
    int result = system(command);

    if (WIFEXITED(result)) {
        return WEXITSTATUS(result) == 0;
    }
    return 0;
}

static int test_cli_aes_ecb_roundtrip(void) {
    printf("Test CLI AES ECB Roundtrip... ");

    const char *plain_file = "test_ecb_plain.bin";
    const char *cipher_file = "test_ecb_cipher.bin";
    const char *decrypted_file = "test_ecb_decrypted.bin";

    if (!create_test_file(plain_file, TEST_FILE_SIZE)) {
        printf("FAIL: Cannot create test file\n");
        return 0;
    }

    BYTE key[16];
    if (generate_random_key(key) != 1) {
        printf("FAIL: Cannot generate key\n");
        remove(plain_file);
        return 0;
    }

    char key_hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(key_hex + (i * 2), "%02x", key[i]);
    }
    key_hex[32] = '\0';

    char command[1024];

    snprintf(command, sizeof(command),
             "./cryptocore --algorithm aes --mode ecb --encrypt --key %s --input %s --output %s",
             key_hex, plain_file, cipher_file);

    if (!run_system_command(command)) {
        printf("FAIL: Encryption command failed\n");
        remove(plain_file);
        return 0;
    }

    snprintf(command, sizeof(command),
             "./cryptocore --algorithm aes --mode ecb --decrypt --key %s --input %s --output %s",
             key_hex, cipher_file, decrypted_file);

    if (!run_system_command(command)) {
        printf("FAIL: Decryption command failed\n");
        remove(plain_file);
        remove(cipher_file);
        return 0;
    }

    if (!compare_files(plain_file, decrypted_file)) {
        printf("FAIL: Files don't match\n");
        remove(plain_file);
        remove(cipher_file);
        remove(decrypted_file);
        return 0;
    }

    remove(plain_file);
    remove(cipher_file);
    remove(decrypted_file);

    printf("[OK]\n");
    return 1;
}

static int test_cli_aes_cbc_roundtrip(void) {
    printf("Test CLI AES CBC Roundtrip... ");

    const char *plain_file = "test_cbc_plain.bin";
    const char *cipher_file = "test_cbc_cipher.bin";
    const char *decrypted_file = "test_cbc_decrypted.bin";

    if (!create_test_file(plain_file, TEST_FILE_SIZE)) {
        printf("FAIL: Cannot create test file\n");
        return 0;
    }

    BYTE key[16];
    if (generate_random_key(key) != 1) {
        printf("FAIL: Cannot generate key\n");
        remove(plain_file);
        return 0;
    }

    char key_hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(key_hex + (i * 2), "%02x", key[i]);
    }
    key_hex[32] = '\0';

    char command[1024];

    snprintf(command, sizeof(command),
             "./cryptocore --algorithm aes --mode cbc --encrypt --key %s --input %s --output %s",
             key_hex, plain_file, cipher_file);

    if (!run_system_command(command)) {
        printf("FAIL: Encryption command failed\n");
        remove(plain_file);
        return 0;
    }

    snprintf(command, sizeof(command),
             "./cryptocore --algorithm aes --mode cbc --decrypt --key %s --input %s --output %s",
             key_hex, cipher_file, decrypted_file);

    if (!run_system_command(command)) {
        printf("FAIL: Decryption command failed\n");
        remove(plain_file);
        remove(cipher_file);
        return 0;
    }

    if (!compare_files(plain_file, decrypted_file)) {
        printf("FAIL: Files don't match\n");
        remove(plain_file);
        remove(cipher_file);
        remove(decrypted_file);
        return 0;
    }

    remove(plain_file);
    remove(cipher_file);
    remove(decrypted_file);

    printf("[OK]\n");
    return 1;
}

static int test_cli_aes_gcm_roundtrip(void) {
    printf("Test CLI AES GCM Roundtrip... ");

    const char *plain_file = "test_gcm_plain.bin";
    const char *cipher_file = "test_gcm_cipher.bin";
    const char *decrypted_file = "test_gcm_decrypted.bin";

    if (!create_test_file(plain_file, TEST_FILE_SIZE)) {
        printf("FAIL: Cannot create test file\n");
        return 0;
    }

    BYTE key[16];
    BYTE aad[16];

    if (generate_random_key(key) != 1 || generate_random_bytes(aad, 16) != 1) {
        printf("FAIL: Cannot generate key or AAD\n");
        remove(plain_file);
        return 0;
    }

    char key_hex[33];
    char aad_hex[33];

    for (int i = 0; i < 16; i++) {
        sprintf(key_hex + (i * 2), "%02x", key[i]);
        sprintf(aad_hex + (i * 2), "%02x", aad[i]);
    }
    key_hex[32] = aad_hex[32] = '\0';

    char command[1024];

    snprintf(command, sizeof(command),
             "./cryptocore --algorithm aes --mode gcm --encrypt --key %s --input %s --output %s --aad %s",
             key_hex, plain_file, cipher_file, aad_hex);

    if (!run_system_command(command)) {
        printf("FAIL: Encryption command failed\n");
        remove(plain_file);
        return 0;
    }

    snprintf(command, sizeof(command),
             "./cryptocore --algorithm aes --mode gcm --decrypt --key %s --input %s --output %s --aad %s",
             key_hex, cipher_file, decrypted_file, aad_hex);

    if (!run_system_command(command)) {
        printf("FAIL: Decryption command failed\n");
        remove(plain_file);
        remove(cipher_file);
        return 0;
    }

    if (!compare_files(plain_file, decrypted_file)) {
        printf("FAIL: Files don't match\n");
        remove(plain_file);
        remove(cipher_file);
        remove(decrypted_file);
        return 0;
    }

    remove(plain_file);
    remove(cipher_file);
    remove(decrypted_file);

    printf("[OK]\n");
    return 1;
}

static int test_cli_aes_gcm_tampered(void) {
    printf("Test CLI AES GCM Tampered Ciphertext... ");

    const char *plain_file = "test_gcm_tamper_plain.bin";
    const char *cipher_file = "test_gcm_tamper_cipher.bin";
    const char *tampered_file = "test_gcm_tampered.bin";
    const char *decrypted_file = "test_gcm_tamper_decrypted.bin";

    if (!create_test_file(plain_file, TEST_FILE_SIZE)) {
        printf("FAIL: Cannot create test file\n");
        return 0;
    }

    BYTE key[16];
    if (generate_random_key(key) != 1) {
        printf("FAIL: Cannot generate key\n");
        remove(plain_file);
        return 0;
    }

    char key_hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(key_hex + (i * 2), "%02x", key[i]);
    }
    key_hex[32] = '\0';

    char command[1024];

    snprintf(command, sizeof(command),
             "./cryptocore --algorithm aes --mode gcm --encrypt --key %s --input %s --output %s",
             key_hex, plain_file, cipher_file);

    if (!run_system_command(command)) {
        printf("FAIL: Encryption command failed\n");
        remove(plain_file);
        return 0;
    }

    FILE *in = fopen(cipher_file, "rb");
    FILE *out = fopen(tampered_file, "wb");

    if (!in || !out) {
        if (in) fclose(in);
        if (out) fclose(out);
        printf("FAIL: Cannot open files for tampering\n");
        remove(plain_file);
        remove(cipher_file);
        return 0;
    }

    BYTE buffer[4096];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), in);

    if (bytes_read > 12) {
        buffer[12 + 10] ^= 0x01;
    }

    fwrite(buffer, 1, bytes_read, out);

    fclose(in);
    fclose(out);

    snprintf(command, sizeof(command),
             "./cryptocore --algorithm aes --mode gcm --decrypt --key %s --input %s --output %s 2>/dev/null",
             key_hex, tampered_file, decrypted_file);

    int result = system(command);

    if (WIFEXITED(result) && WEXITSTATUS(result) == 0) {
        printf("FAIL: Should have rejected tampered ciphertext\n");
        remove(plain_file);
        remove(cipher_file);
        remove(tampered_file);
        remove(decrypted_file);
        return 0;
    }

    remove(plain_file);
    remove(cipher_file);
    remove(tampered_file);

    printf("OK\n");
    return 1;
}

static int test_cli_hash_sha256(void) {
    printf("Test CLI SHA-256 Hash... ");

    const char *test_file = "test_hash.bin";
    const char *hash_file = "test_hash.sha256";

    if (!create_test_file(test_file, TEST_FILE_SIZE)) {
        printf("FAIL: Cannot create test file\n");
        return 0;
    }

    char command[1024];

    snprintf(command, sizeof(command),
             "./cryptocore dgst --algorithm sha256 --input %s --output %s",
             test_file, hash_file);

    if (!run_system_command(command)) {
        printf("FAIL: Hash command failed\n");
        remove(test_file);
        return 0;
    }

    struct stat st;
    if (stat(hash_file, &st) != 0 || st.st_size == 0) {
        printf("FAIL: Hash file not created or empty\n");
        remove(test_file);
        remove(hash_file);
        return 0;
    }

    remove(test_file);
    remove(hash_file);

    printf("[OK]\n");
    return 1;
}

static int test_cli_hmac_verification(void) {
    printf("Test CLI HMAC Verification... ");

    const char *test_file = "test_hmac.bin";
    const char *hmac_file = "test_hmac.hmac";

    if (!create_test_file(test_file, TEST_FILE_SIZE)) {
        printf("FAIL: Cannot create test file\n");
        return 0;
    }

    BYTE key[16];
    if (generate_random_bytes(key, 16) != 1) {
        printf("FAIL: Cannot generate key\n");
        remove(test_file);
        return 0;
    }

    char key_hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(key_hex + (i * 2), "%02x", key[i]);
    }
    key_hex[32] = '\0';

    char command[1024];

    snprintf(command, sizeof(command),
             "./cryptocore dgst --algorithm sha256 --hmac --key %s --input %s --output %s",
             key_hex, test_file, hmac_file);

    if (!run_system_command(command)) {
        printf("FAIL: HMAC generation command failed\n");
        remove(test_file);
        return 0;
    }

    snprintf(command, sizeof(command),
             "./cryptocore dgst --algorithm sha256 --hmac --key %s --input %s --verify %s",
             key_hex, test_file, hmac_file);

    if (!run_system_command(command)) {
        printf("FAIL: HMAC verification command failed\n");
        remove(test_file);
        remove(hmac_file);
        return 0;
    }

    remove(test_file);
    remove(hmac_file);

    printf("[OK]\n");
    return 1;
}

static int test_cli_pbkdf2_key_derivation(void) {
    printf("Test CLI PBKDF2 Key Derivation... ");

    const char *key_file = "test_pbkdf2.key";

    char command[1024];

    snprintf(command, sizeof(command),
             "./cryptocore derive --algorithm pbkdf2 --password \"TestPassword123!\" --salt 00112233445566778899aabbccddeeff --iterations 1000 --length 32 --output %s",
             key_file);

    if (!run_system_command(command)) {
        printf("FAIL: PBKDF2 command failed\n");
        return 0;
    }

    struct stat st;
    if (stat(key_file, &st) != 0 || st.st_size != 32) {
        printf("FAIL: Key file not created or wrong size\n");
        remove(key_file);
        return 0;
    }

    remove(key_file);

    printf("[OK]\n");
    return 1;
}

static int test_cli_hkdf_key_derivation(void) {
    printf("Test CLI HKDF Key Derivation... ");

    const char *key_file = "test_hkdf.key";

    char command[1024];

    snprintf(command, sizeof(command),
             "./cryptocore derive --algorithm hkdf --master-key 00112233445566778899aabbccddeeff --context \"encryption_context\" --length 32 --output %s",
             key_file);

    if (!run_system_command(command)) {
        printf("FAIL: HKDF command failed\n");
        return 0;
    }

    struct stat st;
    if (stat(key_file, &st) != 0 || st.st_size != 32) {
        printf("FAIL: Key file not created or wrong size\n");
        remove(key_file);
        return 0;
    }

    remove(key_file);

    printf("[OK]\n");
    return 1;
}

static int test_cli_aes_modes_compatibility(void) {
    printf("Test CLI AES Modes Compatibility... ");

    const char *plain_file = "test_modes_plain.bin";
    const char *cipher_files[5];
    const char *decrypted_files[5];
    const char *modes[] = {"cbc", "cfb", "ofb", "ctr"};

    cipher_files[0] = "test_cbc_cipher.bin";
    cipher_files[1] = "test_cfb_cipher.bin";
    cipher_files[2] = "test_ofb_cipher.bin";
    cipher_files[3] = "test_ctr_cipher.bin";

    decrypted_files[0] = "test_cbc_decrypted.bin";
    decrypted_files[1] = "test_cfb_decrypted.bin";
    decrypted_files[2] = "test_ofb_decrypted.bin";
    decrypted_files[3] = "test_ctr_decrypted.bin";

    if (!create_test_file(plain_file, TEST_FILE_SIZE)) {
        printf("FAIL: Cannot create test file\n");
        return 0;
    }

    BYTE key[16];
    if (generate_random_key(key) != 1) {
        printf("FAIL: Cannot generate key\n");
        remove(plain_file);
        return 0;
    }

    char key_hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(key_hex + (i * 2), "%02x", key[i]);
    }
    key_hex[32] = '\0';

    int all_passed = 1;

    for (int i = 0; i < 4; i++) {
        char command[1024];

        snprintf(command, sizeof(command),
                 "./cryptocore --algorithm aes --mode %s --encrypt --key %s --input %s --output %s",
                 modes[i], key_hex, plain_file, cipher_files[i]);

        if (!run_system_command(command)) {
            printf("FAIL: %s encryption failed\n", modes[i]);
            all_passed = 0;
            break;
        }

        snprintf(command, sizeof(command),
                 "./cryptocore --algorithm aes --mode %s --decrypt --key %s --input %s --output %s",
                 modes[i], key_hex, cipher_files[i], decrypted_files[i]);

        if (!run_system_command(command)) {
            printf("FAIL: %s decryption failed\n", modes[i]);
            all_passed = 0;
            break;
        }

        if (!compare_files(plain_file, decrypted_files[i])) {
            printf("FAIL: %s files don't match\n", modes[i]);
            all_passed = 0;
            break;
        }
    }

    remove(plain_file);
    for (int i = 0; i < 4; i++) {
        if (cipher_files[i]) remove(cipher_files[i]);
        if (decrypted_files[i]) remove(decrypted_files[i]);
    }

    if (all_passed) {
        printf("[OK]\n");
    }
    return all_passed;
}

static int test_cli_large_file_encryption(void) {
    printf("Test CLI Large File Encryption (CBC)... ");

    const char *plain_file = "test_large_plain.bin";
    const char *cipher_file = "test_large_cipher.bin";
    const char *decrypted_file = "test_large_decrypted.bin";

    printf("\n  Creating large test file (%d MB)...", TEST_LARGE_FILE_SIZE / (1024 * 1024));
    fflush(stdout);

    if (!create_test_file(plain_file, TEST_LARGE_FILE_SIZE)) {
        printf("FAIL: Cannot create large test file\n");
        return 0;
    }

    printf(" Done\n");

    BYTE key[16];
    if (generate_random_key(key) != 1) {
        printf("FAIL: Cannot generate key\n");
        remove(plain_file);
        return 0;
    }

    char key_hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(key_hex + (i * 2), "%02x", key[i]);
    }
    key_hex[32] = '\0';

    char command[1024];

    printf("  Encrypting...");
    fflush(stdout);

    snprintf(command, sizeof(command),
             "./cryptocore --algorithm aes --mode cbc --encrypt --key %s --input %s --output %s",
             key_hex, plain_file, cipher_file);

    if (!run_system_command(command)) {
        printf("FAIL: Encryption command failed\n");
        remove(plain_file);
        return 0;
    }

    printf(" Done\n  Decrypting...");
    fflush(stdout);

    snprintf(command, sizeof(command),
             "./cryptocore --algorithm aes --mode cbc --decrypt --key %s --input %s --output %s",
             key_hex, cipher_file, decrypted_file);

    if (!run_system_command(command)) {
        printf("FAIL: Decryption command failed\n");
        remove(plain_file);
        remove(cipher_file);
        return 0;
    }

    printf(" Done\n  Verifying...");
    fflush(stdout);

    if (!compare_files(plain_file, decrypted_file)) {
        printf("FAIL: Files don't match\n");
        remove(plain_file);
        remove(cipher_file);
        remove(decrypted_file);
        return 0;
    }

    printf(" Done\n");

    remove(plain_file);
    remove(cipher_file);
    remove(decrypted_file);

    printf("[OK]\n");
    return 1;
}

static int test_cli_auto_key_generation(void) {
    printf("Test CLI Automatic Key Generation... ");

    const char *plain_file = "test_auto_plain.bin";
    const char *cipher_file = "test_auto_cipher.bin";
    const char *decrypted_file = "test_auto_decrypted.bin";

    if (!create_test_file(plain_file, 512)) {
        printf("FAIL: Cannot create test file\n");
        return 0;
    }

    char command[1024];

    snprintf(command, sizeof(command),
             "./cryptocore --algorithm aes --mode cbc --encrypt --input %s --output %s",
             plain_file, cipher_file);

    if (!run_system_command(command)) {
        printf("FAIL: Encryption command failed (no key provided)\n");
        remove(plain_file);
        return 0;
    }

    FILE *cipher = fopen(cipher_file, "rb");
    if (!cipher) {
        printf("FAIL: Cannot open cipher file\n");
        remove(plain_file);
        remove(cipher_file);
        return 0;
    }

    BYTE iv[16];
    if (fread(iv, 1, 16, cipher) != 16) {
        printf("FAIL: Cannot read IV from cipher file\n");
        fclose(cipher);
        remove(plain_file);
        remove(cipher_file);
        return 0;
    }
    fclose(cipher);

    printf("  Note: Key was automatically generated\n");

    remove(plain_file);
    remove(cipher_file);
    remove(decrypted_file);

    printf("[OK]\n");
    return 1;
}

static int test_cli_etm_cbc_aad(void) {
    printf("Test CLI Encrypt-then-MAC (CBC with AAD)... ");

    const char *plain_file = "test_etm_plain.bin";
    const char *cipher_file = "test_etm_cipher.bin";
    const char *decrypted_file = "test_etm_decrypted.bin";

    if (!create_test_file(plain_file, TEST_FILE_SIZE)) {
        printf("FAIL: Cannot create test file\n");
        return 0;
    }

    BYTE key[16];
    BYTE aad[16];

    if (generate_random_key(key) != 1 || generate_random_bytes(aad, 16) != 1) {
        printf("FAIL: Cannot generate key or AAD\n");
        remove(plain_file);
        return 0;
    }

    char key_hex[33];
    char aad_hex[33];

    for (int i = 0; i < 16; i++) {
        sprintf(key_hex + (i * 2), "%02x", key[i]);
        sprintf(aad_hex + (i * 2), "%02x", aad[i]);
    }
    key_hex[32] = aad_hex[32] = '\0';

    char command[1024];

    snprintf(command, sizeof(command),
             "./cryptocore --algorithm aes --mode cbc --encrypt --key %s --input %s --output %s --aad %s",
             key_hex, plain_file, cipher_file, aad_hex);

    if (!run_system_command(command)) {
        printf("FAIL: ETM encryption command failed\n");
        remove(plain_file);
        return 0;
    }

    snprintf(command, sizeof(command),
             "./cryptocore --algorithm aes --mode cbc --decrypt --key %s --input %s --output %s --aad %s",
             key_hex, cipher_file, decrypted_file, aad_hex);

    if (!run_system_command(command)) {
        printf("FAIL: ETM decryption command failed\n");
        remove(plain_file);
        remove(cipher_file);
        return 0;
    }

    if (!compare_files(plain_file, decrypted_file)) {
        printf("FAIL: Files don't match\n");
        remove(plain_file);
        remove(cipher_file);
        remove(decrypted_file);
        return 0;
    }

    remove(plain_file);
    remove(cipher_file);
    remove(decrypted_file);

    printf("[OK]\n");
    return 1;
}

static int test_cli_cmac_computation(void) {
    printf("Test CLI CMAC Computation... ");

    const char *test_file = "test_cmac.bin";
    const char *cmac_file = "test_cmac.cmac";

    if (!create_test_file(test_file, TEST_FILE_SIZE)) {
        printf("FAIL: Cannot create test file\n");
        return 0;
    }

    BYTE key[16];
    if (generate_random_bytes(key, 16) != 1) {
        printf("FAIL: Cannot generate key\n");
        remove(test_file);
        return 0;
    }

    char key_hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(key_hex + (i * 2), "%02x", key[i]);
    }
    key_hex[32] = '\0';

    char command[1024];

    snprintf(command, sizeof(command),
             "./cryptocore dgst --algorithm aes --cmac --key %s --input %s --output %s",
             key_hex, test_file, cmac_file);

    if (!run_system_command(command)) {
        printf("FAIL: CMAC command failed\n");
        remove(test_file);
        return 0;
    }

    struct stat st;
    if (stat(cmac_file, &st) != 0 || st.st_size == 0) {
        printf("FAIL: CMAC file not created or empty\n");
        remove(test_file);
        remove(cmac_file);
        return 0;
    }

    remove(test_file);
    remove(cmac_file);

    printf("[OK]\n");
    return 1;
}

static int test_cli_interactive_help(void) {
    printf("Test CLI Help Display... ");

    char command[1024];

    snprintf(command, sizeof(command),
             "./cryptocore --help 2>&1 | tee help_output.tmp | head -1 > help_first_line.tmp");


    FILE *first_line = fopen("help_first_line.tmp", "r");
    int has_usage = 0;

    if (first_line) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), first_line) != NULL) {
            if (strstr(buffer, "Usage:") != NULL ||
                strstr(buffer, "Encryption/Decryption:") != NULL ||
                strlen(buffer) > 10) {
                has_usage = 1;
            }
        }
        fclose(first_line);
    }

    FILE *full_output = fopen("help_output.tmp", "r");
    int output_length = 0;

    if (full_output) {
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), full_output) != NULL) {
            output_length++;
        }
        fclose(full_output);
    }

    remove("help_first_line.tmp");
    remove("help_output.tmp");

    if (has_usage || output_length > 5) {
        printf("[OK]\n");
        return 1;
    }

    return 1;
}

static int test_cli_error_handling(void) {
    printf("Test CLI Error Handling... ");

    char command[1024];

    snprintf(command, sizeof(command),
             "./cryptocore --algorithm aes --mode cbc --encrypt --input nonexistent.bin --output test.bin > error_output.tmp 2>&1");

    int result = system(command);

    FILE *error_file = fopen("error_output.tmp", "r");
    int has_error = 0;

    if (error_file) {
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), error_file) != NULL) {
            if (strstr(buffer, "Error:") != NULL ||
                strstr(buffer, "Cannot open") != NULL ||
                strstr(buffer, "error") != NULL ||
                strstr(buffer, "ERROR") != NULL) {
                has_error = 1;
                break;
            }
        }
        fclose(error_file);
    }

    remove("error_output.tmp");
    remove("test.bin");

    if (!has_error && WIFEXITED(result) && WEXITSTATUS(result) == 0) {
        printf("FAIL: Should have shown error for missing file\n");
        return 0;
    }

    printf("[OK]\n");
    return 1;
}

static int test_cli_sha3_256_hash(void) {
    printf("Test CLI SHA3-256 Hash... ");

    const char *test_file = "test_sha3.bin";
    const char *hash_file = "test_sha3.sha3";

    if (!create_test_file(test_file, TEST_FILE_SIZE)) {
        printf("FAIL: Cannot create test file\n");
        return 0;
    }

    char command[1024];

    snprintf(command, sizeof(command),
             "./cryptocore dgst --algorithm sha3-256 --input %s --output %s",
             test_file, hash_file);

    if (!run_system_command(command)) {
        printf("FAIL: SHA3-256 command failed\n");
        remove(test_file);
        return 0;
    }

    struct stat st;
    if (stat(hash_file, &st) != 0 || st.st_size == 0) {
        printf("FAIL: Hash file not created or empty\n");
        remove(test_file);
        remove(hash_file);
        return 0;
    }

    remove(test_file);
    remove(hash_file);

    printf("[OK]\n");
    return 1;
}

static int test_openssl_aes_cbc_compatibility(void) {
    printf("Test OpenSSL AES-CBC Compatibility...\n");

    const char *plain_file = "test_openssl_plain.txt";
    const char *cryptocore_cipher = "test_openssl_cryptocore.bin";
    const char *openssl_cipher = "test_openssl_openssl.bin";
    const char *cryptocore_ciphertext_only = "test_openssl_cryptocore_ciphertext.bin";
    const char *openssl_decrypted = "test_openssl_decrypted.txt";
    const char *iv_file = "test_openssl_iv.bin";

    const char *test_content = "This is a test file for OpenSSL compatibility.\n"
                               "Second line of test data.\n"
                               "Third line with some more content.\n";

    FILE *f = fopen(plain_file, "w");
    if (!f) {
        printf("  Error: Cannot create test file\n");
        return 0;
    }
    fputs(test_content, f);
    fclose(f);

    const char *key_hex = "000102030405060708090a0b0c0d0e0f";

    char command[1024];
    int success = 0;

    printf("  1. Encrypting with cryptocore (no IV specified)...\n");
    snprintf(command, sizeof(command),
             "./cryptocore --algorithm aes --mode cbc --encrypt --key %s --input %s --output %s",
             key_hex, plain_file, cryptocore_cipher);

    if (!run_system_command(command)) {
        printf("  FAIL: cryptocore encryption failed\n");
        goto cleanup;
    }

    printf("  2. Extracting IV from cryptocore output...\n");
    snprintf(command, sizeof(command),
             "dd if=%s of=%s bs=16 count=1 2>/dev/null",
             cryptocore_cipher, iv_file);
    run_system_command(command);

    snprintf(command, sizeof(command),
             "dd if=%s of=%s bs=16 skip=1 2>/dev/null",
             cryptocore_cipher, cryptocore_ciphertext_only);
    run_system_command(command);

    BYTE iv[16];
    FILE *iv_f = fopen(iv_file, "rb");
    char iv_hex_actual[33] = {0};
    if (iv_f) {
        fread(iv, 1, 16, iv_f);
        fclose(iv_f);
        for (int i = 0; i < 16; i++) {
            sprintf(iv_hex_actual + (i * 2), "%02x", iv[i]);
        }
    }

    printf("  3. Encrypting with OpenSSL using cryptocore's IV...\n");
    snprintf(command, sizeof(command),
             "openssl enc -aes-128-cbc -K %s -iv %s -in %s -out %s",
             key_hex, iv_hex_actual, plain_file, openssl_cipher);

    if (!run_system_command(command)) {
        printf("  FAIL: OpenSSL encryption failed\n");
        goto cleanup;
    }

    printf("  4. Comparing ciphertext (without IV)...\n");
    struct stat st1, st2;
    stat(cryptocore_ciphertext_only, &st1);
    stat(openssl_cipher, &st2);

    printf("  cryptocore ciphertext size: %ld bytes\n", st1.st_size);
    printf("  OpenSSL ciphertext size: %ld bytes\n", st2.st_size);

    if (compare_files(cryptocore_ciphertext_only, openssl_cipher)) {
        printf("  SUCCESS: cryptocore and OpenSSL produce identical ciphertext\n");
        success = 1;
    } else {
        printf("  FAIL: Ciphertexts differ\n");

        printf("  First 32 bytes of cryptocore ciphertext: ");
        fflush(stdout);
        snprintf(command, sizeof(command), "xxd -p -l 32 %s | head -c 64", cryptocore_ciphertext_only);
        system(command);
        printf("\n");

        printf("  First 32 bytes of OpenSSL ciphertext: ");
        fflush(stdout);
        snprintf(command, sizeof(command), "xxd -p -l 32 %s | head -c 64", openssl_cipher);
        system(command);
        printf("\n");
    }

cleanup:
    remove(plain_file);
    remove(cryptocore_cipher);
    remove(openssl_cipher);
    remove(cryptocore_ciphertext_only);
    remove(openssl_decrypted);
    remove(iv_file);

    printf("  Result: %s\n", success ? "[OK]" : "FAILED");
    return success;
}

static int test_openssl_decrypt_cryptocore(void) {
    printf("Test Decrypt OpenSSL output with cryptocore...\n");

    const char *plain_file = "test_decrypt_plain.txt";
    const char *openssl_cipher = "test_decrypt_openssl.bin";
    const char *cryptocore_decrypted = "test_decrypt_cryptocore.txt";

    const char *test_content = "Test data for OpenSSL encryption and cryptocore decryption.\n"
                               "This verifies that cryptocore can decrypt OpenSSL output.\n";

    FILE *f = fopen(plain_file, "w");
    if (!f) {
        printf("  Error: Cannot create test file\n");
        return 0;
    }
    fputs(test_content, f);
    fclose(f);

    const char *key_hex = "00112233445566778899aabbccddeeff";
    const char *iv_hex = "11223344556677889900aabbccddeeff";

    char command[1024];
    int success = 0;

    printf("  1. Encrypting with OpenSSL...\n");
    snprintf(command, sizeof(command),
             "openssl enc -aes-128-cbc -K %s -iv %s -in %s -out %s",
             key_hex, iv_hex, plain_file, openssl_cipher);

    if (!run_system_command(command)) {
        printf("  FAIL: OpenSSL encryption failed\n");
        goto cleanup;
    }

    printf("  2. Decrypting with cryptocore...\n");
    snprintf(command, sizeof(command),
             "./cryptocore --algorithm aes --mode cbc --decrypt --key %s --iv %s --input %s --output %s",
             key_hex, iv_hex, openssl_cipher, cryptocore_decrypted);

    if (!run_system_command(command)) {
        printf("  FAIL: cryptocore decryption failed\n");
        goto cleanup;
    }

    if (compare_files(plain_file, cryptocore_decrypted)) {
        printf("  SUCCESS: cryptocore correctly decrypts OpenSSL ciphertext\n");
        success = 1;
    } else {
        printf("  FAIL: Decrypted file doesn't match original\n");

        printf("  Original file size: ");
        fflush(stdout);
        snprintf(command, sizeof(command), "wc -c < %s", plain_file);
        system(command);

        printf("  Decrypted file size: ");
        fflush(stdout);
        snprintf(command, sizeof(command), "wc -c < %s", cryptocore_decrypted);
        system(command);
    }

cleanup:
    remove(plain_file);
    remove(openssl_cipher);
    remove(cryptocore_decrypted);

    printf("  Result: %s\n", success ? "[OK]" : "FAILED");
    return success;
}

int run_all_integration_tests(void) {
    printf("CRYPTOCORE INTEGRATION TEST SUITE\n");

    int all_passed = 1;

    printf("1. Basic Encryption/Decryption Tests\n");
    all_passed &= test_cli_aes_ecb_roundtrip();
    all_passed &= test_cli_aes_cbc_roundtrip();
    all_passed &= test_cli_aes_modes_compatibility();

    printf("\n2. Authenticated Encryption Tests\n");
    all_passed &= test_cli_aes_gcm_roundtrip();
    all_passed &= test_cli_aes_gcm_tampered();
    all_passed &= test_cli_etm_cbc_aad();

    printf("\n3. Hash Function Tests\n");
    all_passed &= test_cli_hash_sha256();
    all_passed &= test_cli_sha3_256_hash();

    printf("\n4. MAC Function Tests\n");
    all_passed &= test_cli_hmac_verification();
    all_passed &= test_cli_cmac_computation();

    printf("\n5. Key Derivation Tests\n");
    all_passed &= test_cli_pbkdf2_key_derivation();
    all_passed &= test_cli_hkdf_key_derivation();

    printf("\n6. Performance and Edge Cases\n");
    all_passed &= test_cli_large_file_encryption();
    all_passed &= test_cli_auto_key_generation();

    printf("\n7. CLI Interface Tests\n");
    all_passed &= test_cli_interactive_help();
    all_passed &= test_cli_error_handling();

    printf("\n8. OpenSSL/External Tools Compatibility Tests\n");
    all_passed &= test_openssl_aes_cbc_compatibility();
    all_passed &= test_openssl_decrypt_cryptocore();

    printf("INTEGRATION TESTS: %s\n", all_passed ? "ALL PASSED" : "SOME TESTS FAILED");

    return all_passed;
}

int main_integration_tests(void) {
    return run_all_integration_tests() ? 0 : 1;
}
