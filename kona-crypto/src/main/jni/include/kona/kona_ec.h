/*
 * Copyright (C) 2025, THL A29 Limited, a Tencent company. All rights reserved.
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

#include <stdbool.h>
#include <string.h>

#include <jni.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

int ec_pri_key_len(const EC_GROUP* group);
int ec_pub_key_len(const EC_GROUP* group);

EVP_PKEY* ec_pri_key(int curveNID, const uint8_t* pri_key, size_t pri_key_len);
EVP_PKEY* ec_pub_key(int curveNID, const uint8_t* pub_key, size_t pub_key_len);

BIGNUM* ec_pri_key_bn(const EC_GROUP* group, const uint8_t* pri_key_bytes);
EC_POINT* ec_pub_key_point(const EC_GROUP* group, const uint8_t* pub_key_bytes, size_t pub_key_len);

int ec_check_point_order(const EC_GROUP* group, const EC_POINT *point);
int ec_validate_point(EC_GROUP* group, EC_POINT *point);

EVP_PKEY_CTX* ec_create_pkey_ctx(EVP_PKEY* pkey);
uint8_t* ec_gen_key_pair(const EC_GROUP* group, EVP_PKEY_CTX* ctx, size_t* key_pair_len);

typedef struct {
    EVP_PKEY* pkey;
    EVP_PKEY_CTX* pctx;
    EVP_MD_CTX* mctx;
} ECDSA_CTX;

ECDSA_CTX* ecdsa_create_ctx(int md_nid, EVP_PKEY* pkey, bool is_sign);
void ECDSA_CTX_free(ECDSA_CTX* ctx);
uint8_t* ecdsa_sign(EVP_MD_CTX* ctx, const uint8_t* msg, size_t msg_len, size_t* sig_len);
int ecdsa_verify(EVP_MD_CTX* ctx, const uint8_t* msg, size_t msg_len, const uint8_t* sig, size_t sig_len);
