/*
 * main.c
 *
 *  Created on: 27 сент. 2025 г.
 *      Author: sergey
 */

#include "../include/main.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void generate_random_iv(BYTE *iv) {
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        for (int i = 0; i < IV_SIZE; i++) {
            iv[i] = rand() % 256;
        }
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
    printf("\n");
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

int main(int argc, char *argv[]) {
    config_t config;
    BYTE *input_data = NULL;
    BYTE *output_data = NULL;
    BYTE actual_iv[IV_SIZE];
    size_t input_len, output_len;
    int success = 0;

    if (!parse_arguments(argc, argv, &config)) {
        print_usage(argv[0]);
        return 1;
    }

    if (!read_file(config.input_file, &input_data, &input_len)) {
        fprintf(stderr, "Error: Cannot read input file '%s'\n", config.input_file);
        return 1;
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
