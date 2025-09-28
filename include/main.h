/*
 * main.h
 *
 *  Created on: 27 сент. 2025 г.
 *      Author: sergey
 */

#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define BLOCK_SIZE 16
#define AES_128_KEY_SIZE 16
#define MAX_PATH_LEN 1024
#define IV_SIZE 16

typedef unsigned char BYTE;

typedef enum {
    MODE_ENCRYPT,
    MODE_DECRYPT
} operation_mode_t;

typedef enum {
    MODE_ECB,
    MODE_CBC,
    MODE_CFB,
    MODE_OFB,
    MODE_CTR
} cipher_mode_t;

typedef struct {
    char algorithm[16];
    cipher_mode_t mode;
    operation_mode_t operation;
    BYTE key[AES_128_KEY_SIZE];
    BYTE iv[IV_SIZE];
    char input_file[MAX_PATH_LEN];
    char output_file[MAX_PATH_LEN];
    int iv_provided;
    int force_format;
} config_t;

int parse_arguments(int argc, char *argv[], config_t *config);
void print_usage(const char *program_name);
int hex_string_to_bytes(const char *hex_string, BYTE *bytes, size_t bytes_len);
void print_hex(const BYTE *data, size_t len);

int read_file(const char *filename, BYTE **data, size_t *data_len);
int write_file(const char *filename, const BYTE *data, size_t data_len);

int ecb_encrypt(const BYTE *key, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);
int ecb_decrypt(const BYTE *key, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);

int cbc_encrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);
int cbc_decrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);

int cfb_encrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);
int cfb_decrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);

int ofb_encrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);
int ofb_decrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);

int ctr_encrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);
int ctr_decrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);

void generate_random_iv(BYTE *iv);
int requires_padding(cipher_mode_t mode);
void xor_blocks(const BYTE *a, const BYTE *b, BYTE *result, size_t len);

#endif



