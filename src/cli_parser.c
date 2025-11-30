/*
 * cli_parser.c
 *
 *  Created on: 27 сент. 2025 г.
 *      Author: sergey
 */

#include "../include/main.h"
#include "../include/sha256.h"
#include "../include/sha3_256.h"
#include "../include/hmac.h"
#include "../include/cmac.h"
#include <string.h>
#include <ctype.h>

void print_usage(const char *program_name) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  Encryption/Decryption: %s --algorithm aes --mode MODE --encrypt|--decrypt [--key KEY] --input INPUT_FILE [--output OUTPUT_FILE] [--iv IV]\n", program_name);
    fprintf(stderr, "  Hashing: %s dgst --algorithm ALGORITHM --input INPUT_FILE [--output OUTPUT_FILE]\n", program_name);
    fprintf(stderr, "  HMAC: %s dgst --algorithm sha256 --hmac --key KEY --input INPUT_FILE [--output OUTPUT_FILE] [--verify VERIFY_FILE]\n", program_name);
    fprintf(stderr, "  CMAC: %s dgst --algorithm aes --cmac --key KEY --input INPUT_FILE [--output OUTPUT_FILE] [--verify VERIFY_FILE]\n", program_name);
    fprintf(stderr, "  Testing: %s --input TEST_COMMAND\n", program_name);
    fprintf(stderr, "\nEncryption/Decryption Arguments:\n");
    fprintf(stderr, "  --algorithm ALGORITHM    Cipher algorithm (only 'aes' supported)\n");
    fprintf(stderr, "  --mode MODE              Mode of operation (ecb, cbc, cfb, ofb, ctr)\n");
    fprintf(stderr, "  --encrypt                Encrypt the input file\n");
    fprintf(stderr, "  --decrypt                Decrypt the input file\n");
    fprintf(stderr, "  --key KEY                128-bit key as hexadecimal string (32 characters, optional for encryption)\n");
    fprintf(stderr, "  --input INPUT_FILE       Input file path\n");
    fprintf(stderr, "  --output OUTPUT_FILE     Output file path (optional)\n");
    fprintf(stderr, "  --iv IV                  Initialization vector as hexadecimal string (32 characters, for decryption only)\n");
    fprintf(stderr, "\nHash Arguments:\n");
    fprintf(stderr, "  dgst                     Compute message digest\n");
    fprintf(stderr, "  --algorithm ALGORITHM    Hash algorithm (sha256, sha3-256)\n");
    fprintf(stderr, "  --input INPUT_FILE       Input file path\n");
    fprintf(stderr, "  --output OUTPUT_FILE     Output file path (optional)\n");
    fprintf(stderr, "\nHMAC Arguments:\n");
    fprintf(stderr, "  dgst                     Compute HMAC\n");
    fprintf(stderr, "  --algorithm sha256       Must be 'sha256' for HMAC\n");
    fprintf(stderr, "  --hmac                   Use HMAC mode\n");
    fprintf(stderr, "  --key KEY                Key as hexadecimal string (arbitrary length)\n");
    fprintf(stderr, "  --input INPUT_FILE       Input file path\n");
    fprintf(stderr, "  --output OUTPUT_FILE     Output file path (optional)\n");
    fprintf(stderr, "  --verify VERIFY_FILE     Verify against HMAC in file\n");
    fprintf(stderr, "\nCMAC Arguments:\n");
    fprintf(stderr, "  dgst                     Compute CMAC\n");
    fprintf(stderr, "  --algorithm aes          Must be 'aes' for CMAC\n");
    fprintf(stderr, "  --cmac                   Use AES-CMAC mode\n");
    fprintf(stderr, "  --key KEY                Key as hexadecimal string (32 characters)\n");
    fprintf(stderr, "  --input INPUT_FILE       Input file path\n");
    fprintf(stderr, "  --output OUTPUT_FILE     Output file path (optional)\n");
    fprintf(stderr, "  --verify VERIFY_FILE     Verify against CMAC in file\n");
    fprintf(stderr, "\nTesting Commands:\n");
    fprintf(stderr, "  --input --test-keys      Run CSPRNG key tests\n");
    fprintf(stderr, "  --input --test-nist      Generate 10MB file for NIST tests\n");
    fprintf(stderr, "  --input --test-hash      Run hash function tests\n");
    fprintf(stderr, "  --input --test-mac       Run MAC function tests\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  Encryption:              %s --algorithm aes --mode cbc --encrypt --input plain.txt --output cipher.bin\n", program_name);
    fprintf(stderr, "  Decryption:              %s --algorithm aes --mode cbc --decrypt --key 000102...0f --input cipher.bin --output decrypted.txt\n", program_name);
    fprintf(stderr, "  SHA-256 hash:            %s dgst --algorithm sha256 --input document.pdf\n", program_name);
    fprintf(stderr, "  HMAC-SHA-256:            %s dgst --algorithm sha256 --hmac --key 001122...ff --input message.txt\n", program_name);
    fprintf(stderr, "  AES-CMAC:                %s dgst --algorithm aes --cmac --key 001122...ff --input message.txt --output message.cmac\n", program_name);
    fprintf(stderr, "  HMAC verification:       %s dgst --algorithm sha256 --hmac --key 001122...ff --input message.txt --verify expected.hmac\n", program_name);
    fprintf(stderr, "  Key tests:               %s --input --test-keys\n", program_name);
    fprintf(stderr, "  Hash tests:              %s --input --test-hash\n", program_name);
    fprintf(stderr, "  MAC tests:               %s --input --test-mac\n", program_name);
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
    int dgst_flag = 0;

    memset(config, 0, sizeof(config_t));
    config->iv_provided = 0;
    config->key_provided = 0;
    config->hmac_mode = 0;
    config->cmac_mode = 0;
    config->verify_mode = 0;
    config->algorithm = ALG_AES;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "dgst") == 0) {
            dgst_flag = 1;
            break;
        }
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--input") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "--test-keys") == 0 ||
                strcmp(argv[i + 1], "--test-nist") == 0 ||
                strcmp(argv[i + 1], "--test-hash") == 0 ||
                strcmp(argv[i + 1], "--test-mac") == 0) {
                strncpy(config->input_file, argv[i + 1], sizeof(config->input_file) - 1);
                config->input_file[sizeof(config->input_file) - 1] = '\0';
                return 1;
            }
        }
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "dgst") == 0) {
            continue;
        }
        else if (strcmp(argv[i], "--algorithm") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --algorithm requires an argument\n");
                return 0;
            }
            char *algo_str = argv[++i];

            if (dgst_flag) {
                if (strcmp(algo_str, "sha256") == 0) {
                    config->algorithm = ALG_SHA256;
                } else if (strcmp(algo_str, "sha3-256") == 0) {
                    config->algorithm = ALG_SHA3_256;
                } else if (strcmp(algo_str, "aes") == 0) {
                    config->algorithm = ALG_AES;
                } else {
                    fprintf(stderr, "Error: Unsupported algorithm '%s'. Supported: sha256, sha3-256, aes (with --cmac)\n", algo_str);
                    return 0;
                }
            } else {
                if (strcmp(algo_str, "aes") != 0) {
                    fprintf(stderr, "Error: Only 'aes' algorithm is supported for encryption\n");
                    return 0;
                }
                config->algorithm = ALG_AES;
            }
        }
        else if (strcmp(argv[i], "--mode") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --mode requires an argument\n");
                return 0;
            }
            if (dgst_flag) {
                fprintf(stderr, "Error: --mode not allowed for hash/MAC operations\n");
                return 0;
            }
            char *mode_str = argv[++i];
            if (strcmp(mode_str, "ecb") == 0) {
                config->mode = MODE_ECB;
            } else if (strcmp(mode_str, "cbc") == 0) {
                config->mode = MODE_CBC;
            } else if (strcmp(mode_str, "cfb") == 0) {
                config->mode = MODE_CFB;
            } else if (strcmp(mode_str, "ofb") == 0) {
                config->mode = MODE_OFB;
            } else if (strcmp(mode_str, "ctr") == 0) {
                config->mode = MODE_CTR;
            } else {
                fprintf(stderr, "Error: Unsupported mode '%s'. Supported modes: ecb, cbc, cfb, ofb, ctr\n", mode_str);
                return 0;
            }
        }
        else if (strcmp(argv[i], "--encrypt") == 0) {
            if (dgst_flag) {
                fprintf(stderr, "Error: --encrypt not allowed for hash/MAC operations\n");
                return 0;
            }
            encrypt_flag = 1;
            config->operation = MODE_ENCRYPT;
        }
        else if (strcmp(argv[i], "--decrypt") == 0) {
            if (dgst_flag) {
                fprintf(stderr, "Error: --decrypt not allowed for hash/MAC operations\n");
                return 0;
            }
            decrypt_flag = 1;
            config->operation = MODE_DECRYPT;
        }
        else if (strcmp(argv[i], "--hmac") == 0) {
            if (!dgst_flag) {
                fprintf(stderr, "Error: --hmac only allowed for dgst command\n");
                return 0;
            }
            config->hmac_mode = 1;
        }
        else if (strcmp(argv[i], "--cmac") == 0) {
            if (!dgst_flag) {
                fprintf(stderr, "Error: --cmac only allowed for dgst command\n");
                return 0;
            }
            config->cmac_mode = 1;
        }
        else if (strcmp(argv[i], "--key") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --key requires an argument\n");
                return 0;
            }

            if (config->hmac_mode) {
                char *key_hex = argv[++i];
                size_t key_len = strlen(key_hex);
                if (key_len % 2 != 0) {
                    fprintf(stderr, "Error: Key must be hexadecimal string with even length\n");
                    return 0;
                }
                size_t byte_len = key_len / 2;
                BYTE *key_bytes = malloc(byte_len);
                if (!key_bytes) {
                    fprintf(stderr, "Error: Memory allocation failed for key\n");
                    return 0;
                }
                if (!hex_string_to_bytes(key_hex, key_bytes, byte_len)) {
                    fprintf(stderr, "Error: Invalid key format\n");
                    free(key_bytes);
                    return 0;
                }
                memcpy(config->key, key_bytes, (byte_len < 16) ? byte_len : 16);
                free(key_bytes);
                config->key_provided = 1;
            } else if (config->cmac_mode) {
                if (!hex_string_to_bytes(argv[++i], config->key, AES_128_KEY_SIZE)) {
                    fprintf(stderr, "Error: Invalid CMAC key format. Must be 32-character hexadecimal string\n");
                    return 0;
                }
                config->key_provided = 1;
            } else {
                if (!hex_string_to_bytes(argv[++i], config->key, AES_128_KEY_SIZE)) {
                    fprintf(stderr, "Error: Invalid key format. Must be 32-character hexadecimal string\n");
                    return 0;
                }
                config->key_provided = 1;
            }
        }
        else if (strcmp(argv[i], "--iv") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --iv requires an argument\n");
                return 0;
            }
            if (dgst_flag) {
                fprintf(stderr, "Error: --iv not allowed for hash/MAC operations\n");
                return 0;
            }
            if (!hex_string_to_bytes(argv[++i], config->iv, IV_SIZE)) {
                fprintf(stderr, "Error: Invalid IV format. Must be 32-character hexadecimal string\n");
                return 0;
            }
            config->iv_provided = 1;
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
        else if (strcmp(argv[i], "--verify") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --verify requires an argument\n");
                return 0;
            }
            if (!dgst_flag || (!config->hmac_mode && !config->cmac_mode)) {
                fprintf(stderr, "Error: --verify only allowed for HMAC or CMAC operations\n");
                return 0;
            }
            strncpy(config->verify_file, argv[++i], sizeof(config->verify_file) - 1);
            config->verify_file[sizeof(config->verify_file) - 1] = '\0';
            config->verify_mode = 1;
        }
        else {
            fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
            return 0;
        }
    }

    if (dgst_flag) {
        if (config->hmac_mode && config->cmac_mode) {
            fprintf(stderr, "Error: Cannot specify both --hmac and --cmac\n");
            return 0;
        }

        if (config->algorithm == ALG_AES && !config->cmac_mode) {
            fprintf(stderr, "Error: Algorithm 'aes' can only be used with --cmac flag\n");
            return 0;
        }
        if (config->hmac_mode && config->algorithm != ALG_SHA256) {
            fprintf(stderr, "Error: HMAC requires --algorithm sha256\n");
            return 0;
        }
        if (config->cmac_mode && config->algorithm != ALG_AES) {
            fprintf(stderr, "Error: CMAC requires --algorithm aes\n");
            return 0;
        }

        if (config->hmac_mode) {
            if (!config->key_provided) {
                fprintf(stderr, "Error: --key is required for HMAC operations\n");
                return 0;
            }
        }

        if (config->cmac_mode) {
            if (!config->key_provided) {
                fprintf(stderr, "Error: --key is required for CMAC operations\n");
                return 0;
            }
        }

        if (config->verify_mode && !(config->hmac_mode || config->cmac_mode)) {
            fprintf(stderr, "Error: --verify requires --hmac or --cmac\n");
            return 0;
        }

        if (strlen(config->input_file) == 0) {
            fprintf(stderr, "Error: --input is required for hash/MAC operations\n");
            return 0;
        }

        return 1;
    }

    if (!encrypt_flag && !decrypt_flag && config->algorithm == ALG_AES) {
        fprintf(stderr, "Error: Either --encrypt or --decrypt must be specified for encryption operations\n");
        return 0;
    }
    if (encrypt_flag && decrypt_flag) {
        fprintf(stderr, "Error: Cannot specify both --encrypt and --decrypt\n");
        return 0;
    }

    if (config->operation == MODE_DECRYPT && !config->key_provided) {
        fprintf(stderr, "Error: --key is required for decryption\n");
        return 0;
    }

    if (config->operation == MODE_ENCRYPT && !config->key_provided) {
        if (generate_random_key(config->key) != 1) {
            fprintf(stderr, "Error: Failed to generate random key\n");
            return 0;
        }
        printf("Generated random key: ");
        print_hex(config->key, AES_128_KEY_SIZE);
    }

    if (config->operation == MODE_ENCRYPT && config->iv_provided) {
        fprintf(stderr, "Warning: --iv is ignored during encryption (IV is generated automatically)\n");
        config->iv_provided = 0;
    }

    if (config->operation == MODE_DECRYPT && config->mode != MODE_ECB && !config->iv_provided) {
        fprintf(stderr, "Warning: --iv not provided for decryption in mode %d. Will try to read from file.\n", config->mode);
    }

    if (strlen(config->input_file) == 0) {
        fprintf(stderr, "Error: --input is required\n");
        return 0;
    }

    if (strlen(config->output_file) == 0 && config->algorithm == ALG_AES) {
        char base_name[MAX_PATH_LEN];
        get_base_name(config->input_file, base_name, sizeof(base_name));

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

