/*
 * pbkdf2.h
 *
 *  Created on: 20 дек. 2025 г.
 *      Author: sergey
 */

#ifndef INCLUDE_PBKDF2_H_
#define INCLUDE_PBKDF2_H_

#include "main.h"
#include <stddef.h>

int pbkdf2_hmac_sha256(const BYTE *password, size_t password_len,
                       const BYTE *salt, size_t salt_len,
                       unsigned int iterations,
                       size_t dklen,
                       BYTE *derived_key);

#endif /* INCLUDE_PBKDF2_H_ */
