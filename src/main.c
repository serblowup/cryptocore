/*
 * main.c
 *
 *  Created on: 27 сент. 2025 г.
 *      Author: sergey
 */

#include "../include/main.h"

int main(int argc, char *argv[]) {
    config_t config;
    BYTE *input_data = NULL;
    BYTE *output_data = NULL;
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
        if (!ecb_encrypt(config.key, input_data, input_len, &output_data, &output_len)) {
            fprintf(stderr, "Error: Encryption failed\n");
            goto cleanup;
        }
    } else {
        if (!ecb_decrypt(config.key, input_data, input_len, &output_data, &output_len)) {
            fprintf(stderr, "Error: Decryption failed\n");
            goto cleanup;
        }
    }

    if (!write_file(config.output_file, output_data, output_len)) {
        fprintf(stderr, "Error: Cannot write output file '%s'\n", config.output_file);
        goto cleanup;
    }

    printf("Success: %s -> %s\n", config.input_file, config.output_file);
    success = 1;

cleanup:
    if (input_data) free(input_data);
    if (output_data) free(output_data);

    return success ? 0 : 1;
}
