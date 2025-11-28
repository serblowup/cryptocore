/*
 * sha3_256.h
 *
 *  Created on: 27 нояб. 2025 г.
 *      Author: sergey
 */

#ifndef INCLUDE_SHA3_256_H_
#define INCLUDE_SHA3_256_H_

#include <stdint.h>
#include <stddef.h>

#define SHA3_256_DIGEST_SIZE 32

typedef unsigned char BYTE;

int sha3_256_hash(const BYTE *data, size_t len, BYTE *digest);

#endif /* INCLUDE_SHA3_256_H_ */
