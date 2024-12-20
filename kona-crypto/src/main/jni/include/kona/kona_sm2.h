/*
 * Copyright (C) 2024, THL A29 Limited, a Tencent company. All rights reserved.
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

#include <openssl/ec.h>

typedef struct {
    const uint8_t* id;
    size_t id_len;
} SM2_ID;

const SM2_ID* sm2_id();

typedef struct {
    const uint8_t* field;
    size_t field_len;

    const uint8_t* order;
    size_t order_len;

    const uint8_t* a;
    size_t a_len;

    const uint8_t* b;
    size_t b_len;

    const uint8_t* gen_x;
    size_t gen_x_len;

    const uint8_t* gen_y;
    size_t gen_y_len;
} SM2_CURVE;

const SM2_CURVE* sm2_curve();

const EC_GROUP* sm2_group();

BIGNUM* sm2_pri_key(const uint8_t* pri_key_bytes);
EC_POINT* sm2_pub_key(const uint8_t* pub_key_bytes, size_t pub_key_len);
int sm2_validate_point(EC_POINT *point);

EVP_PKEY* sm2_load_pub_key(const uint8_t* pub_key, size_t pub_key_len);
EVP_PKEY* sm2_load_key_pair(const uint8_t* pri_key, const uint8_t* pub_key);
int sm2_gen_pub_key(const uint8_t* pri_key, uint8_t* pub_key);
EVP_PKEY_CTX* sm2_create_pkey_ctx(EVP_PKEY* pkey);

int sm2_gen_key_pair(EVP_PKEY_CTX* ctx, uint8_t* key_pair, size_t* key_pair_len);

typedef struct {
    EVP_PKEY* pkey;
    EVP_PKEY_CTX* pctx;
} SM2_CIPHER_CTX;

uint8_t* sm2_encrypt(EVP_PKEY_CTX* ctx, const uint8_t* plaintext, size_t plaintext_len, size_t* ciphertext_len);
uint8_t* sm2_decrypt(EVP_PKEY_CTX* ctx, const uint8_t* ciphertext, size_t ciphertext_len, size_t* cleartext_len);
void sm2_cipher_ctx_free(SM2_CIPHER_CTX* ctx);

typedef struct {
    EVP_PKEY* pkey;
    EVP_PKEY_CTX* pctx;
    EVP_MD_CTX* mctx;
} SM2_SIGNATURE_CTX;

SM2_SIGNATURE_CTX* sm2_create_md_ctx(EVP_PKEY* pkey, const uint8_t* id, size_t id_len, bool is_sign);
uint8_t* sm2_sign(EVP_MD_CTX* ctx, const uint8_t* msg, size_t msg_len, size_t* sig_len);
int sm2_verify(EVP_MD_CTX* ctx, const uint8_t* msg, size_t msg_len, const uint8_t* sig, size_t sig_len);
void sm2_signature_ctx_free(SM2_SIGNATURE_CTX* ctx);

typedef struct {
    EVP_MD_CTX* sm3_ctx;
    BN_CTX* bn_ctx;
} SM2_KEYEX_CTX;

typedef struct {
    BIGNUM* pri_key;
    EC_POINT* pub_key;
    BIGNUM* e_pri_key;
    uint8_t* id;
    size_t id_len;

    EC_POINT* peer_pub_key;
    EC_POINT* peer_e_pub_key;
    uint8_t* peer_id;
    size_t peer_id_len;
} SM2_KEYEX_PARAMS;

SM2_KEYEX_CTX* sm2_create_keyex_ctx();
void sm2_free_keyex_ctx(SM2_KEYEX_CTX* ctx);
int sm2_derive_key(uint8_t* key_out, int key_len, SM2_KEYEX_CTX* ctx, const SM2_KEYEX_PARAMS* params, bool is_initiator);
void sm2_keyex_params_free(SM2_KEYEX_PARAMS* ctx);
