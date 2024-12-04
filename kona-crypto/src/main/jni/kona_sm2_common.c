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
#include <stdlib.h>
#include <string.h>

#include <jni.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "kona/kona_common.h"

EVP_PKEY* load_pub_key(const uint8_t* pub_key, size_t pub_key_len) {
    EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    if (key_ctx == NULL) {
        OPENSSL_print_err();
        return NULL;
    }

    if (!EVP_PKEY_fromdata_init(key_ctx)) {
        OPENSSL_print_err();
        EVP_PKEY_CTX_free(key_ctx);
        return NULL;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "SM2", 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)pub_key, pub_key_len),
        OSSL_PARAM_construct_end()
    };

    EVP_PKEY* pkey = NULL;
    if (!EVP_PKEY_fromdata(key_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params)) {
        OPENSSL_print_err();
        EVP_PKEY_CTX_free(key_ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(key_ctx);
    return pkey;
}

EVP_PKEY* load_key_pair(const uint8_t* pri_key, const uint8_t* pub_key) {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (ec_key == NULL) {
        OPENSSL_print_err();
        return NULL;
    }

    BIGNUM* pri_key_bn = BN_bin2bn(pri_key, SM2_PRI_KEY_LEN, NULL);
    if (pri_key_bn == NULL) {
        OPENSSL_print_err();
        EC_KEY_free(ec_key);

        return NULL;
    }

    if (!EC_KEY_set_private_key(ec_key, pri_key_bn)) {
        OPENSSL_print_err();
        BN_free(pri_key_bn);
        EC_KEY_free(ec_key);

        return NULL;
    }

    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    EC_POINT* pub_point = EC_POINT_new(group);
    if (pub_point == NULL) {
        OPENSSL_print_err();
        BN_free(pri_key_bn);
        EC_KEY_free(ec_key);

        return NULL;
    }

    if (!EC_POINT_oct2point(group, pub_point, pub_key, SM2_PUB_KEY_LEN, NULL)) {
        OPENSSL_print_err();
        BN_free(pri_key_bn);
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);

        return NULL;
    }

    if (!EC_KEY_set_public_key(ec_key, pub_point)) {
        OPENSSL_print_err();
        BN_free(pri_key_bn);
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);

        return NULL;
    }

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        OPENSSL_print_err();

        BN_free(pri_key_bn);
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);

        return NULL;
    }

    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        OPENSSL_print_err();
        EVP_PKEY_free(pkey);

        BN_free(pri_key_bn);
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);

        return NULL;
    }

    BN_free(pri_key_bn);
    EC_POINT_free(pub_point);
    ec_key = NULL; // ec_key cannot be freed due pkey is using it.

    return pkey;
}

int sm2_gen_pub_key(const uint8_t* pri_key, uint8_t* pub_key) {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (ec_key == NULL) {
        return OPENSSL_FAILURE;
    }

    BIGNUM* bn_pri_key = BN_bin2bn(pri_key, SM2_PRI_KEY_LEN, NULL);
    if (bn_pri_key == NULL) {
        EC_KEY_free(ec_key);
        return OPENSSL_FAILURE;
    }

    if (!EC_KEY_set_private_key(ec_key, bn_pri_key)) {
        EC_KEY_free(ec_key);
        BN_free(bn_pri_key);
        return OPENSSL_FAILURE;
    }

    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    if (group == NULL) {
        EC_KEY_free(ec_key);
        BN_free(bn_pri_key);
        return OPENSSL_FAILURE;
    }

    EC_POINT* pub_point = EC_POINT_new(group);
    if (pub_point == NULL) {
        EC_KEY_free(ec_key);
        BN_free(bn_pri_key);
        return OPENSSL_FAILURE;
    }

    if (!EC_POINT_mul(group, pub_point, bn_pri_key, NULL, NULL, NULL)) {
        EC_KEY_free(ec_key);
        BN_free(bn_pri_key);
        EC_POINT_free(pub_point);
        return OPENSSL_FAILURE;
    }

    if (!EC_KEY_set_public_key(ec_key, pub_point)) {
        EC_KEY_free(ec_key);
        BN_free(bn_pri_key);
        EC_POINT_free(pub_point);
        return OPENSSL_FAILURE;
    }

    BN_CTX* bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        EC_KEY_free(ec_key);
        BN_free(bn_pri_key);
        EC_POINT_free(pub_point);
        return OPENSSL_FAILURE;
    }

    size_t pub_key_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bn_ctx);
    if (pub_key_len != SM2_PUB_KEY_LEN) {
        EC_KEY_free(ec_key);
        BN_free(bn_pri_key);
        EC_POINT_free(pub_point);
        BN_CTX_free(bn_ctx);
        return OPENSSL_FAILURE;
    }

    if (!EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, pub_key, pub_key_len, bn_ctx)) {
        EC_KEY_free(ec_key);
        BN_free(bn_pri_key);
        EC_POINT_free(pub_point);
        BN_CTX_free(bn_ctx);
        return OPENSSL_FAILURE;
    }

    EC_KEY_free(ec_key);
    BN_free(bn_pri_key);
    EC_POINT_free(pub_point);
    BN_CTX_free(bn_ctx);

    return OPENSSL_SUCCESS;
}

EVP_PKEY_CTX* sm2_create_pkey_ctx(EVP_PKEY* pkey) {
    EVP_PKEY_CTX* ctx = NULL;

    if (pkey != NULL) {
        ctx = EVP_PKEY_CTX_new(pkey, NULL);
    } else {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    }

    if (ctx == NULL) {
        OPENSSL_print_err();
        return NULL;
    }

    return ctx;
}
