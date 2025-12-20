/*
 * hkdf.h
 *
 *  Created on: 20 дек. 2025 г.
 *      Author: sergey
 */

#ifndef INCLUDE_HKDF_H_
#define INCLUDE_HKDF_H_

#include "main.h"
#include <stddef.h>

int derive_key_from_master(const BYTE *master_key, size_t master_key_len,
                          const char *context,
                          size_t derived_key_len,
                          BYTE *derived_key);

#endif /* INCLUDE_HKDF_H_ */
