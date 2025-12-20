/*
 * main.c
 *
 *  Created on: 27 сент. 2025 г.
 *      Author: sergey
 */

#include "../include/main.h"
#include "../include/sha256.h"
#include "../include/sha3_256.h"
#include "../include/hmac.h"
#include "../include/cmac.h"
#include "../include/gcm.h"
#include "../include/etm.h"
#include "../include/pbkdf2.h"
#include "../include/hkdf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int run_all_key_tests(void);
int generate_nist_test_file(const char* filename, size_t size_bytes);
void print_nist_instructions(void);

void generate_random_iv(BYTE *iv) {
    if (generate_random_bytes(iv, IV_SIZE) != 1) {
        fprintf(stderr, "Fatal error: Failed to generate IV\n");
        exit(EXIT_FAILURE);
    }
}

void generate_random_nonce(BYTE *nonce) {
    if (generate_random_bytes(nonce, GCM_NONCE_SIZE) != 1) {
        fprintf(stderr, "Fatal error: Failed to generate nonce\n");
        exit(EXIT_FAILURE);
    }
}

int requires_padding(cipher_mode_t mode) {
    return (mode == MODE_ECB || mode == MODE_CBC);
}

void xor_blocks(const BYTE *a, const BYTE *b, BYTE *result, size_t len) {
    for (size_t i = 0; i < len; i++) {
        result[i] = a[i] ^ b[i];
    }
}

void print_hex(const BYTE *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

int detect_file_format(const BYTE *data, size_t data_len, cipher_mode_t mode, const BYTE *user_iv) {
    (void)user_iv;
    (void)data;
    (void)mode;

    printf("DEBUG: File size: %zu bytes\n", data_len);

    if (data_len == 320) {
        printf("DEBUG: 320 bytes - assuming OpenSSL format (no IV)\n");
        return 0;
    } else if (data_len == 336) {
        printf("DEBUG: 336 bytes - assuming our format (with IV)\n");
        return 1;
    } else if (data_len % BLOCK_SIZE == 0) {
        printf("DEBUG: Multiple of 16 - assuming OpenSSL format (no IV)\n");
        return 0;
    } else if ((data_len - IV_SIZE) % BLOCK_SIZE == 0) {
        printf("DEBUG: (Size-16) multiple of 16 - assuming our format (with IV)\n");
        return 1;
    } else {
        printf("DEBUG: Defaulting to OpenSSL format (no IV)\n");
        return 0;
    }
}

static int compute_hmac(config_t *config, const char *input_file, const char *output_file, const char *verify_file) {
    BYTE *input_data = NULL;
    size_t input_len;
    BYTE digest[32];
    char mac_hex[65];
    int success = 0;

    if (!read_file(input_file, &input_data, &input_len)) {
        fprintf(stderr, "Error: Cannot read input file '%s'\n", input_file);
        return 0;
    }

    if (!hmac_file_compute(config->key, 16, input_file, digest, 8192)) {
        fprintf(stderr, "Error: HMAC-SHA256 computation failed\n");
        goto cleanup;
    }

    if (config->verify_mode) {
        BYTE *verify_data = NULL;
        size_t verify_len;

        if (!read_file(verify_file, &verify_data, &verify_len)) {
            fprintf(stderr, "Error: Cannot read verify file '%s'\n", verify_file);
            goto cleanup;
        }

        char *expected_hex = strtok((char*)verify_data, " \t\n");
        if (!expected_hex) {
            fprintf(stderr, "Error: Invalid verify file format\n");
            free(verify_data);
            goto cleanup;
        }

        BYTE expected_digest[32];
        size_t expected_len = strlen(expected_hex);
        if (expected_len != 64) { // 32 bytes * 2
            fprintf(stderr, "Error: Expected HMAC length mismatch\n");
            free(verify_data);
            goto cleanup;
        }

        if (!hex_string_to_bytes(expected_hex, expected_digest, 32)) {
            fprintf(stderr, "Error: Invalid HMAC format in verify file\n");
            free(verify_data);
            goto cleanup;
        }

        free(verify_data);

        if (memcmp(digest, expected_digest, 32) == 0) {
            printf("[OK] HMAC verification successful\n");
            success = 1;
        } else {
            printf("[ERROR] HMAC verification failed\n");
            success = 0;
        }
    } else {
        for (size_t i = 0; i < 32; i++) {
            sprintf(mac_hex + (i * 2), "%02x", digest[i]);
        }
        mac_hex[64] = '\0';

        if (output_file && strlen(output_file) > 0) {
            FILE *file = fopen(output_file, "w");
            if (!file) {
                fprintf(stderr, "Error: Cannot open output file '%s'\n", output_file);
                goto cleanup;
            }
            fprintf(file, "%s %s\n", mac_hex, input_file);
            fclose(file);
            printf("HMAC written to: %s\n", output_file);
        } else {
            printf("%s %s\n", mac_hex, input_file);
        }
        success = 1;
    }

cleanup:
    if (input_data) free(input_data);
    return success;
}

static int compute_cmac(config_t *config, const char *input_file, const char *output_file, const char *verify_file) {
    BYTE *input_data = NULL;
    size_t input_len;
    BYTE digest[16];
    char mac_hex[33];
    int success = 0;

    if (!read_file(input_file, &input_data, &input_len)) {
        fprintf(stderr, "Error: Cannot read input file '%s'\n", input_file);
        return 0;
    }

    if (!cmac_file_compute(config->key, input_file, digest)) {
        fprintf(stderr, "Error: CMAC computation failed\n");
        goto cleanup;
    }

    if (config->verify_mode) {
        BYTE *verify_data = NULL;
        size_t verify_len;

        if (!read_file(verify_file, &verify_data, &verify_len)) {
            fprintf(stderr, "Error: Cannot read verify file '%s'\n", verify_file);
            goto cleanup;
        }

        char *expected_hex = strtok((char*)verify_data, " \t\n");
        if (!expected_hex) {
            fprintf(stderr, "Error: Invalid verify file format\n");
            free(verify_data);
            goto cleanup;
        }

        BYTE expected_digest[16];
        size_t expected_len = strlen(expected_hex);
        if (expected_len != 32) { // 16 bytes * 2
            fprintf(stderr, "Error: Expected CMAC length mismatch\n");
            free(verify_data);
            goto cleanup;
        }

        if (!hex_string_to_bytes(expected_hex, expected_digest, 16)) {
            fprintf(stderr, "Error: Invalid CMAC format in verify file\n");
            free(verify_data);
            goto cleanup;
        }

        free(verify_data);

        if (memcmp(digest, expected_digest, 16) == 0) {
            printf("[OK] CMAC verification successful\n");
            success = 1;
        } else {
            printf("[ERROR] CMAC verification failed\n");
            success = 0;
        }
    } else {
        for (size_t i = 0; i < 16; i++) {
            sprintf(mac_hex + (i * 2), "%02x", digest[i]);
        }
        mac_hex[32] = '\0';

        if (output_file && strlen(output_file) > 0) {
            FILE *file = fopen(output_file, "w");
            if (!file) {
                fprintf(stderr, "Error: Cannot open output file '%s'\n", output_file);
                goto cleanup;
            }
            fprintf(file, "%s %s\n", mac_hex, input_file);
            fclose(file);
            printf("CMAC written to: %s\n", output_file);
        } else {
            printf("%s %s\n", mac_hex, input_file);
        }
        success = 1;
    }

cleanup:
    if (input_data) free(input_data);
    return success;
}

static int compute_hash(algorithm_t algorithm, const char *input_file, const char *output_file) {
    BYTE *input_data = NULL;
    size_t input_len;
    BYTE digest[32];
    char hash_hex[65];
    int success = 0;

    if (!read_file(input_file, &input_data, &input_len)) {
        fprintf(stderr, "Error: Cannot read input file '%s'\n", input_file);
        return 0;
    }

    switch (algorithm) {
        case ALG_SHA256:
            if (input_len > 10 * 1024 * 1024) {
                printf("Large file detected, using chunk processing...\n");
                if (!sha256_file_hash(input_file, digest, 8192)) {
                    fprintf(stderr, "Error: SHA-256 computation failed\n");
                    goto cleanup;
                }
            } else {
                sha256_hash(input_data, input_len, digest);
            }
            break;
        case ALG_SHA3_256:
            if (!sha3_256_hash(input_data, input_len, digest)) {
                fprintf(stderr, "Error: SHA3-256 computation failed\n");
                goto cleanup;
            }
            break;
        default:
            fprintf(stderr, "Error: Unsupported hash algorithm\n");
            goto cleanup;
    }

    for (int i = 0; i < 32; i++) {
        sprintf(hash_hex + (i * 2), "%02x", digest[i]);
    }
    hash_hex[64] = '\0';

    if (output_file && strlen(output_file) > 0) {
        FILE *file = fopen(output_file, "w");
        if (!file) {
            fprintf(stderr, "Error: Cannot open output file '%s'\n", output_file);
            goto cleanup;
        }
        fprintf(file, "%s %s\n", hash_hex, input_file);
        fclose(file);
        printf("Hash written to: %s\n", output_file);
    } else {
        printf("%s %s\n", hash_hex, input_file);
    }

    success = 1;

cleanup:
    if (input_data) free(input_data);
    return success;
}

static int handle_gcm_encryption(config_t *config, BYTE *input_data, size_t input_len,
                                 BYTE **output_data, size_t *output_len) {
    if (!config->nonce_provided) {
        generate_random_nonce(config->nonce);
    }

    if (!gcm_encrypt_full(config->key,
                         input_data, input_len,
                         config->aad_provided ? config->aad_data : NULL,
                         config->aad_len,
                         output_data, output_len)) {
        fprintf(stderr, "Error: GCM encryption failed\n");
        return 0;
    }

    return 1;
}

static int handle_gcm_decryption(config_t *config, BYTE *input_data, size_t input_len,
                                 BYTE **output_data, size_t *output_len) {
    if (input_len < GCM_NONCE_SIZE + GCM_TAG_SIZE) {
        fprintf(stderr, "Error: Input file too small for GCM (needs at least %d bytes for nonce + tag)\n",
                GCM_NONCE_SIZE + GCM_TAG_SIZE);
        return 0;
    }

    if (config->nonce_provided) {
        printf("Using user-provided nonce via --iv\n");

        if (!gcm_decrypt_full(config->key,
                             input_data, input_len,
                             config->aad_provided ? config->aad_data : NULL,
                             config->aad_len,
                             output_data, output_len)) {
            fprintf(stderr, "Error: GCM authentication failed - AAD mismatch or ciphertext tampered\n");
            return 0;
        }
    } else {
        printf("Reading nonce from file (first 12 bytes)\n");

        if (!gcm_decrypt_full(config->key,
                             input_data, input_len,
                             config->aad_provided ? config->aad_data : NULL,
                             config->aad_len,
                             output_data, output_len)) {
            fprintf(stderr, "Error: GCM authentication failed - AAD mismatch or ciphertext tampered\n");
            return 0;
        }
    }

    return 1;
}

static int handle_etm_encryption(config_t *config, BYTE *input_data, size_t input_len,
                                BYTE **output_data, size_t *output_len) {
    if (!encrypt_then_mac(config->mode,
                         config->key, AES_128_KEY_SIZE,
                         input_data, input_len,
                         config->aad_provided ? config->aad_data : NULL,
                         config->aad_len,
                         output_data, output_len)) {
        fprintf(stderr, "Error: ETM encryption failed\n");
        return 0;
    }
    return 1;
}

static int handle_etm_decryption(config_t *config, BYTE *input_data, size_t input_len,
                                BYTE **output_data, size_t *output_len) {
    if (!decrypt_then_verify(config->mode,
                            config->key, AES_128_KEY_SIZE,
                            input_data, input_len,
                            config->aad_provided ? config->aad_data : NULL,
                            config->aad_len,
                            output_data, output_len)) {
        fprintf(stderr, "Error: ETM authentication failed - AAD mismatch or ciphertext tampered\n");
        return 0;
    }
    return 1;
}

static int handle_kdf_derivation(config_t *config) {
    BYTE derived_key[MAX_KDF_KEY_LENGTH];
    BYTE password_bytes[MAX_PATH_LEN];
    size_t password_len = 0;

    printf("Key Derivation Parameters:\n");
    printf("  Algorithm:   %s\n", config->kdf_algorithm);
    printf("  Iterations:  %u\n", config->iterations);
    printf("  Key Length:  %zu bytes\n", config->key_length);

    if (config->algorithm == ALG_PBKDF2) {
        printf("  Mode:        PBKDF2-HMAC-SHA256\n");

        password_len = strlen(config->password);
        if (password_len >= MAX_PATH_LEN) {
            fprintf(stderr, "Error: Password too long\n");
            return 0;
        }
        memcpy(password_bytes, config->password, password_len);

        if (config->salt_provided) {
            printf("  Salt:        Provided (%s, %zu bytes)\n",
                   config->salt_hex, config->salt_len);
        } else {
            config->salt_len = 16;
            if (generate_random_bytes(config->salt_data, config->salt_len) != 1) {
                fprintf(stderr, "Error: Failed to generate random salt\n");
                return 0;
            }

            for (size_t i = 0; i < config->salt_len; i++) {
                sprintf(config->salt_hex + (i * 2), "%02x", config->salt_data[i]);
            }
            config->salt_hex[config->salt_len * 2] = '\0';

            printf("  Salt:        Randomly generated (%zu bytes)\n", config->salt_len);
        }

        printf("  Password:    Provided (%zu characters)\n", password_len);
        printf("Deriving key... ");
        fflush(stdout);

        if (!pbkdf2_hmac_sha256(password_bytes, password_len,
                               config->salt_data, config->salt_len,
                               config->iterations,
                               config->key_length,
                               derived_key)) {
            fprintf(stderr, "Error: PBKDF2 derivation failed\n");
            return 0;
        }

        printf("Done\n");

    } else if (config->algorithm == ALG_HKDF) {
        printf("  Mode:        HKDF\n");

        if (!config->key_provided) {
            fprintf(stderr, "Error: Master key required for HKDF\n");
            return 0;
        }

        password_len = strlen(config->password);
        if (password_len == 0) {
            fprintf(stderr, "Error: Context string required for HKDF\n");
            return 0;
        }

        printf("  Context:     %s\n", config->password);
        printf("Deriving key... ");
        fflush(stdout);

        if (!derive_key_from_master(config->key, AES_128_KEY_SIZE,
                                   config->password,
                                   config->key_length,
                                   derived_key)) {
            fprintf(stderr, "Error: HKDF derivation failed\n");
            return 0;
        }

        printf("Done\n");
        config->salt_len = 0;
        memset(config->salt_data, 0, sizeof(config->salt_data));
        memset(config->salt_hex, 0, sizeof(config->salt_hex));

    } else {
        fprintf(stderr, "Error: Unsupported KDF algorithm\n");
        return 0;
    }

    printf("Result: ");
    print_hex(derived_key, config->key_length);
    printf(" ");
    print_hex(config->salt_data, config->salt_len);
    printf("\n");

    if (strlen(config->output_file) > 0) {
        if (!write_file(config->output_file, derived_key, config->key_length)) {
            fprintf(stderr, "Error: Cannot write key to file '%s'\n", config->output_file);
            return 0;
        }
        printf("Key written to: %s (%zu bytes)\n", config->output_file, config->key_length);
    }

    memset(password_bytes, 0, sizeof(password_bytes));
    memset(derived_key, 0, sizeof(derived_key));

    return 1;
}

int main(int argc, char *argv[]) {
    config_t config;
    BYTE *input_data = NULL;
    BYTE *output_data = NULL;
    BYTE actual_iv[IV_SIZE];
    size_t input_len, output_len;
    int success = 0;
    int dgst_mode = 0;
    int derive_mode = 0;

    OPENSSL_init_ssl(0, NULL);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "dgst") == 0) {
            dgst_mode = 1;
            break;
        }
        if (strcmp(argv[i], "derive") == 0) {
            derive_mode = 1;
            break;
        }
    }

    if (!parse_arguments(argc, argv, &config)) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(config.input_file, "--test-keys") == 0) {
        return run_all_key_tests() ? 0 : 1;
    }

    if (strcmp(config.input_file, "--test-nist") == 0) {
        if (generate_nist_test_file("nist_test_data.bin", 10000000)) {
            print_nist_instructions();
            return 0;
        } else {
            return 1;
        }
    }

    if (strcmp(config.input_file, "--test-hash") == 0) {
        return run_hash_tests() ? 0 : 1;
    }

    if (strcmp(config.input_file, "--test-mac") == 0) {
        return run_all_mac_tests() ? 0 : 1;
    }

    if (strcmp(config.input_file, "--test-aead") == 0) {
        return run_aead_tests() ? 0 : 1;
    }

    if (strcmp(config.input_file, "--test-kdf") == 0) {
        return run_all_kdf_tests() ? 0 : 1;
    }

    if (derive_mode) {
        success = handle_kdf_derivation(&config);
        goto cleanup;
    }

    if (dgst_mode) {
            if (config.hmac_mode) {
                success = compute_hmac(&config, config.input_file,
                                    strlen(config.output_file) > 0 ? config.output_file : NULL,
                                    strlen(config.verify_file) > 0 ? config.verify_file : NULL);
            } else if (config.cmac_mode) {
                success = compute_cmac(&config, config.input_file,
                                     strlen(config.output_file) > 0 ? config.output_file : NULL,
                                     strlen(config.verify_file) > 0 ? config.verify_file : NULL);
            } else if (config.algorithm == ALG_SHA256 || config.algorithm == ALG_SHA3_256) {
                success = compute_hash(config.algorithm, config.input_file,
                                     strlen(config.output_file) > 0 ? config.output_file : NULL);
            } else {
                fprintf(stderr, "Error: Unsupported algorithm for dgst command\n");
            }
            goto cleanup;
        }

        if (!read_file(config.input_file, &input_data, &input_len)) {
            fprintf(stderr, "Error: Cannot read input file '%s'\n", config.input_file);
            return 1;
        }

        if (config.key_provided && is_weak_key(config.key, AES_128_KEY_SIZE)) {
            fprintf(stderr, "Warning: The provided key appears to be weak. Consider using a stronger key.\n");
        }

        if (config.mode == MODE_GCM) {
            if (config.operation == MODE_ENCRYPT) {
                success = handle_gcm_encryption(&config, input_data, input_len, &output_data, &output_len);
            } else {
                success = handle_gcm_decryption(&config, input_data, input_len, &output_data, &output_len);
            }

            if (!success) {
                goto cleanup;
            }

            if (!write_file(config.output_file, output_data, output_len)) {
                fprintf(stderr, "Error: Cannot write output file '%s'\n", config.output_file);
                goto cleanup;
            }

            printf("GCM %s completed successfully\n",
                   config.operation == MODE_ENCRYPT ? "encryption" : "decryption");
            printf("Output written to: %s\n", config.output_file);

            free(input_data);
            if (output_data) free(output_data);
            return 0;
        } else if (config.etm_mode) {
            if (config.operation == MODE_ENCRYPT) {
                success = handle_etm_encryption(&config, input_data, input_len, &output_data, &output_len);
            } else {
                success = handle_etm_decryption(&config, input_data, input_len, &output_data, &output_len);
            }

            if (!success) {
                goto cleanup;
            }

            if (!write_file(config.output_file, output_data, output_len)) {
                fprintf(stderr, "Error: Cannot write output file '%s'\n", config.output_file);
                goto cleanup;
            }

            printf("ETM (%s) %s completed successfully\n",
                   config.mode == MODE_CBC ? "CBC" :
                   config.mode == MODE_CTR ? "CTR" :
                   config.mode == MODE_CFB ? "CFB" : "OFB",
                   config.operation == MODE_ENCRYPT ? "encryption" : "decryption");
            printf("Output written to: %s\n", config.output_file);

            free(input_data);
            if (output_data) free(output_data);
            return 0;
        }



        if (config.operation == MODE_ENCRYPT) {
            if (config.mode != MODE_ECB) {
                generate_random_iv(actual_iv);
            }
        } else {
            if (config.mode == MODE_ECB) {
            } else if (config.iv_provided) {
                memcpy(actual_iv, config.iv, IV_SIZE);

                int is_our_format = detect_file_format(input_data, input_len, config.mode, config.iv);

                if (is_our_format) {
                    memmove(input_data, input_data + IV_SIZE, input_len - IV_SIZE);
                    input_len -= IV_SIZE;
                    printf("Removed IV from file\n");
                } else {
                    printf("Using full file as ciphertext (OpenSSL format)\n");
                }
            } else {
                if (input_len < IV_SIZE) {
                    fprintf(stderr, "Error: Input file too short to contain IV\n");
                    goto cleanup;
                }
                memcpy(actual_iv, input_data, IV_SIZE);
                memmove(input_data, input_data + IV_SIZE, input_len - IV_SIZE);
                input_len -= IV_SIZE;
                printf("Read IV from file\n");
            }
        }

        int result = 0;
        if (config.operation == MODE_ENCRYPT) {
            switch (config.mode) {
                case MODE_ECB:
                    result = ecb_encrypt(config.key, input_data, input_len, &output_data, &output_len);
                    break;
                case MODE_CBC:
                    result = cbc_encrypt(config.key, actual_iv, input_data, input_len, &output_data, &output_len);
                    break;
                case MODE_CFB:
                    result = cfb_encrypt(config.key, actual_iv, input_data, input_len, &output_data, &output_len);
                    break;
                case MODE_OFB:
                    result = ofb_encrypt(config.key, actual_iv, input_data, input_len, &output_data, &output_len);
                    break;
                case MODE_CTR:
                    result = ctr_encrypt(config.key, actual_iv, input_data, input_len, &output_data, &output_len);
                    break;
                default:
                    fprintf(stderr, "Error: Unsupported mode for encryption\n");
                    goto cleanup;
            }
        } else {
            switch (config.mode) {
                case MODE_ECB:
                    result = ecb_decrypt(config.key, input_data, input_len, &output_data, &output_len);
                    break;
                case MODE_CBC:
                    result = cbc_decrypt(config.key, actual_iv, input_data, input_len, &output_data, &output_len);
                    break;
                case MODE_CFB:
                    result = cfb_decrypt(config.key, actual_iv, input_data, input_len, &output_data, &output_len);
                    break;
                case MODE_OFB:
                    result = ofb_decrypt(config.key, actual_iv, input_data, input_len, &output_data, &output_len);
                    break;
                case MODE_CTR:
                    result = ctr_decrypt(config.key, actual_iv, input_data, input_len, &output_data, &output_len);
                    break;
                default:
                    fprintf(stderr, "Error: Unsupported mode for decryption\n");
                    goto cleanup;
            }
        }

        if (!result) {
            fprintf(stderr, "Error: %s failed\n", config.operation == MODE_ENCRYPT ? "Encryption" : "Decryption");
            goto cleanup;
        }

        if (config.operation == MODE_ENCRYPT && config.mode != MODE_ECB) {
            BYTE *final_output = malloc(IV_SIZE + output_len);
            if (!final_output) {
                fprintf(stderr, "Error: Memory allocation failed\n");
                goto cleanup;
            }
            memcpy(final_output, actual_iv, IV_SIZE);
            memcpy(final_output + IV_SIZE, output_data, output_len);

            if (!write_file(config.output_file, final_output, IV_SIZE + output_len)) {
                fprintf(stderr, "Error: Cannot write output file '%s'\n", config.output_file);
                free(final_output);
                goto cleanup;
            }
            free(final_output);
        } else {
            if (!write_file(config.output_file, output_data, output_len)) {
                fprintf(stderr, "Error: Cannot write output file '%s'\n", config.output_file);
                goto cleanup;
            }
        }

        printf("Success: %s -> %s\n", config.input_file, config.output_file);
        success = 1;

cleanup:
    if (input_data) free(input_data);
    if (output_data) free(output_data);

    return success ? 0 : 1;
}
