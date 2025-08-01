/*
 * Copyright (C) 2024, Tencent. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <openssl/err.h>

#define SM2_PRI_KEY_LEN      32
#define SM2_PUB_KEY_LEN      65
#define SM2_COMP_PUB_KEY_LEN 33
#define SM3_DIGEST_LEN       32
#define SM3_MAC_LEN          32
#define SM4_KEY_LEN          16
#define SM4_GCM_TAG_LEN      16

#define PRI_KEY_MIN_LEN      32
#define PUB_KEY_MIN_LEN      65

#define OPENSSL_SUCCESS       1
#define OPENSSL_FAILURE       0

#define KONA_print(...) fprintf(stdout, __VA_ARGS__), fprintf(stdout, "\n")
#define KONA_print_err(...) fprintf(stderr, __VA_ARGS__), fprintf(stderr, "\n")
#define OPENSSL_print_err() ERR_print_errors_fp(stderr)

uint8_t* bn2bin(BIGNUM* bn);
void bin2hex(const uint8_t* bytes, size_t offset, size_t len, uint8_t* hex);
uint8_t* hex2bin(const char* hex);

void print_hex(const uint8_t* bytes, size_t offset, size_t len);
