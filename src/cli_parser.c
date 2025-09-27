/*
 * cli_parser.c
 *
 *  Created on: 27 сент. 2025 г.
 *      Author: sergey
 */

#include "../include/main.h"
#include <string.h>
#include <ctype.h>

void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s --algorithm aes --mode ecb --encrypt|--decrypt --key KEY --input INPUT_FILE [--output OUTPUT_FILE]\n", program_name);
    fprintf(stderr, "\nArguments:\n");
    fprintf(stderr, "  --algorithm ALGORITHM    Cipher algorithm (only 'aes' supported)\n");
    fprintf(stderr, "  --mode MODE              Mode of operation (only 'ecb' supported)\n");
    fprintf(stderr, "  --encrypt                Encrypt the input file\n");
    fprintf(stderr, "  --decrypt                Decrypt the input file\n");
    fprintf(stderr, "  --key KEY                128-bit key as hexadecimal string (32 characters)\n");
    fprintf(stderr, "  --input INPUT_FILE       Input file path\n");
    fprintf(stderr, "  --output OUTPUT_FILE     Output file path (optional)\n");
    fprintf(stderr, "\nExample:\n");
    fprintf(stderr, "  %s --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plain.txt --output cipher.bin\n", program_name);
}

int hex_string_to_bytes(const char *hex_string, BYTE *bytes, size_t bytes_len) {
    size_t hex_len = strlen(hex_string);
    if (hex_len != bytes_len * 2) {
        return 0;
    }

    for (size_t i = 0; i < hex_len; i += 2) {
        if (!isxdigit(hex_string[i]) || !isxdigit(hex_string[i+1])) {
            return 0;
        }
        sscanf(hex_string + i, "%2hhx", &bytes[i/2]);
    }
    return 1;
}

static void get_base_name(const char *path, char *base_name, size_t base_name_size) {
    const char *filename = strrchr(path, '/');
    if (filename == NULL) {
        filename = strrchr(path, '\\');
    }

    if (filename != NULL) {
        filename++;
    } else {
        filename = path;
    }

    strncpy(base_name, filename, base_name_size - 1);
    base_name[base_name_size - 1] = '\0';

    char *dot = strrchr(base_name, '.');
    if (dot != NULL) {
        *dot = '\0';
    }
}

int parse_arguments(int argc, char *argv[], config_t *config) {
    int encrypt_flag = 0;
    int decrypt_flag = 0;

    memset(config, 0, sizeof(config_t));

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--algorithm") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --algorithm requires an argument\n");
                return 0;
            }
            strncpy(config->algorithm, argv[++i], sizeof(config->algorithm) - 1);
            config->algorithm[sizeof(config->algorithm) - 1] = '\0';
        }
        else if (strcmp(argv[i], "--mode") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --mode requires an argument\n");
                return 0;
            }
            strncpy(config->mode, argv[++i], sizeof(config->mode) - 1);
            config->mode[sizeof(config->mode) - 1] = '\0';
        }
        else if (strcmp(argv[i], "--encrypt") == 0) {
            encrypt_flag = 1;
            config->operation = MODE_ENCRYPT;
        }
        else if (strcmp(argv[i], "--decrypt") == 0) {
            decrypt_flag = 1;
            config->operation = MODE_DECRYPT;
        }
        else if (strcmp(argv[i], "--key") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --key requires an argument\n");
                return 0;
            }
            if (!hex_string_to_bytes(argv[++i], config->key, AES_128_KEY_SIZE)) {
                fprintf(stderr, "Error: Invalid key format. Must be 32-character hexadecimal string\n");
                return 0;
            }
        }
        else if (strcmp(argv[i], "--input") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --input requires an argument\n");
                return 0;
            }
            strncpy(config->input_file, argv[++i], sizeof(config->input_file) - 1);
            config->input_file[sizeof(config->input_file) - 1] = '\0';
        }
        else if (strcmp(argv[i], "--output") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --output requires an argument\n");
                return 0;
            }
            strncpy(config->output_file, argv[++i], sizeof(config->output_file) - 1);
            config->output_file[sizeof(config->output_file) - 1] = '\0';
        }
        else {
            fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
            return 0;
        }
    }

    if (strlen(config->algorithm) == 0) {
        fprintf(stderr, "Error: --algorithm is required\n");
        return 0;
    }
    if (strcmp(config->algorithm, "aes") != 0) {
        fprintf(stderr, "Error: Only 'aes' algorithm is supported\n");
        return 0;
    }

    if (strlen(config->mode) == 0) {
        fprintf(stderr, "Error: --mode is required\n");
        return 0;
    }
    if (strcmp(config->mode, "ecb") != 0) {
        fprintf(stderr, "Error: Only 'ecb' mode is supported\n");
        return 0;
    }

    if (!encrypt_flag && !decrypt_flag) {
        fprintf(stderr, "Error: Either --encrypt or --decrypt must be specified\n");
        return 0;
    }
    if (encrypt_flag && decrypt_flag) {
        fprintf(stderr, "Error: Cannot specify both --encrypt and --decrypt\n");
        return 0;
    }

    if (strlen(config->input_file) == 0) {
        fprintf(stderr, "Error: --input is required\n");
        return 0;
    }

    if (strlen(config->output_file) == 0) {
        char base_name[MAX_PATH_LEN];
        get_base_name(config->input_file, base_name, sizeof(base_name));

        // Безопасное формирование имени файла
        if (config->operation == MODE_ENCRYPT) {
            snprintf(config->output_file, sizeof(config->output_file), "%.*s.enc",
                    (int)(sizeof(config->output_file) - 5), base_name);
        } else {
            snprintf(config->output_file, sizeof(config->output_file), "%.*s.dec",
                    (int)(sizeof(config->output_file) - 5), base_name);
        }
    }

    return 1;
}
