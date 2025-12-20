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
#include <time.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#define BLOCK_SIZE 16
#define AES_128_KEY_SIZE 16
#define MAX_PATH_LEN 1024
#define IV_SIZE 16
#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE 16
#define MAX_AAD_SIZE 1024
#define MAX_KDF_KEY_LENGTH 256
#define MAX_SALT_LENGTH 64

typedef unsigned char BYTE;

typedef enum {
    MODE_ENCRYPT,
    MODE_DECRYPT,
    MODE_DERIVE
} operation_mode_t;

typedef enum {
    MODE_ECB,
    MODE_CBC,
    MODE_CFB,
    MODE_OFB,
    MODE_CTR,
    MODE_GCM
} cipher_mode_t;

typedef enum {
    ALG_AES,
    ALG_SHA256,
    ALG_SHA3_256,
    ALG_HMAC,
    ALG_CMAC,
    ALG_PBKDF2,
    ALG_HKDF
} algorithm_t;

typedef struct {
    algorithm_t algorithm;
    cipher_mode_t mode;
    operation_mode_t operation;
    BYTE key[AES_128_KEY_SIZE];
    BYTE iv[IV_SIZE];
    BYTE nonce[GCM_NONCE_SIZE];
    BYTE aad_data[MAX_AAD_SIZE];
    size_t aad_len;
    char input_file[MAX_PATH_LEN];
    char output_file[MAX_PATH_LEN];
    char verify_file[MAX_PATH_LEN];
    char aad_hex[MAX_PATH_LEN];

    char password[MAX_PATH_LEN];
    char salt_hex[MAX_PATH_LEN * 2];
    unsigned int iterations;
    size_t key_length;
    size_t salt_len;
    BYTE salt_data[MAX_SALT_LENGTH];
    char kdf_algorithm[MAX_PATH_LEN];

    int iv_provided;
    int nonce_provided;
    int aad_provided;
    int force_format;
    int key_provided;
    int hmac_mode;
    int cmac_mode;
    int verify_mode;
    int gcm_mode;
    int etm_mode;

    int salt_provided;
    int password_provided;
    int derive_mode;
} config_t;

int generate_random_bytes(uint8_t* buffer, size_t num_bytes);
int generate_random_key(BYTE* key);
int is_weak_key(const BYTE* key, size_t key_len);
int test_key_uniqueness(void);
int generate_nist_test_file(const char* filename, size_t size_bytes);

int parse_arguments(int argc, char *argv[], config_t *config);
void print_usage(const char *program_name);
int hex_string_to_bytes(const char *hex_string, BYTE *bytes, size_t bytes_len);
int is_hex_string(const char *str);  // <-- НОВАЯ ФУНКЦИЯ
void print_hex(const BYTE *data, size_t len);
int read_file(const char *filename, BYTE **data, size_t *data_len);
int write_file(const char *filename, const BYTE *data, size_t data_len);

int process_file_in_chunks(const char *filename, void (*process_chunk)(const BYTE *chunk, size_t chunk_len, void *context), void *context, size_t chunk_size);
int get_file_size(const char *filename, size_t *file_size);

int ecb_encrypt(const BYTE *key, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);
int ecb_encrypt_no_padding(const BYTE *key, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);
int ecb_decrypt(const BYTE *key, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);
int cbc_encrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);
int cbc_decrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);
int cfb_encrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);
int cfb_decrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);
int ofb_encrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);
int ofb_decrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);
int ctr_encrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);
int ctr_decrypt(const BYTE *key, const BYTE *iv, const BYTE *input, size_t input_len, BYTE **output, size_t *output_len);

int gcm_encrypt_full(const BYTE *key,
                     const BYTE *plaintext, size_t plaintext_len,
                     const BYTE *aad, size_t aad_len,
                     BYTE **output, size_t *output_len);

int gcm_decrypt_full(const BYTE *key,
                     const BYTE *input, size_t input_len,
                     const BYTE *aad, size_t aad_len,
                     BYTE **output, size_t *output_len);

int encrypt_then_mac(cipher_mode_t enc_mode,
                     const BYTE *key, size_t key_len,
                     const BYTE *plaintext, size_t plaintext_len,
                     const BYTE *aad, size_t aad_len,
                     BYTE **output, size_t *output_len);

int decrypt_then_verify(cipher_mode_t enc_mode,
                        const BYTE *key, size_t key_len,
                        const BYTE *input, size_t input_len,
                        const BYTE *aad, size_t aad_len,
                        BYTE **output, size_t *output_len);

void generate_random_iv(BYTE *iv);
void generate_random_nonce(BYTE *nonce);
int requires_padding(cipher_mode_t mode);
void xor_blocks(const BYTE *a, const BYTE *b, BYTE *result, size_t len);

int run_hash_tests(void);
int run_all_mac_tests(void);
int run_aead_tests(void);
int run_all_kdf_tests(void);

#endif /* MAIN_H */
