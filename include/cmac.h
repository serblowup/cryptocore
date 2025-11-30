/*
 * cmac.h
 *
 *  Created on: 29 нояб. 2025 г.
 *      Author: sergey
 */

#ifndef INCLUDE_CMAC_H_
#define INCLUDE_CMAC_H_

#include "main.h"
#include <stddef.h>

#define CMAC_DIGEST_SIZE 16
#define CMAC_BLOCK_SIZE 16

int cmac_compute(const BYTE *key, const BYTE *data, size_t data_len, BYTE *digest);
int cmac_verify(const BYTE *key, const BYTE *data, size_t data_len, const BYTE *expected_digest);
int cmac_file_compute(const BYTE *key, const char *filename, BYTE *digest);
void cmac_generate_subkeys(const BYTE *key, BYTE *k1, BYTE *k2);

#endif /* INCLUDE_CMAC_H_ */
