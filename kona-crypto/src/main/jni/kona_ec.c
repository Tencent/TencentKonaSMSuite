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

#include <stdlib.h>
#include <string.h>

#include <jni.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "kona/kona_common.h"
#include "kona/kona_ec.h"

int ec_pri_key_len(const EC_GROUP* group) {
    int degree = EC_GROUP_get_degree(group);
    return (degree + 7) / 8;
}

int ec_pub_key_len(const EC_GROUP* group) {
    return 1 + ec_pri_key_len(group) * 2;
}

EVP_PKEY* ec_pri_key(int curveNID, const uint8_t* pri_key, size_t pri_key_len) {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(curveNID);
    if (!ec_key) return NULL;

    BIGNUM *pri_key_bn = BN_bin2bn(pri_key, pri_key_len, NULL);
    if (!pri_key_bn || !EC_KEY_set_private_key(ec_key, pri_key_bn)) {
        EC_KEY_free(ec_key);
        BN_free(pri_key_bn);
        return NULL;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || !EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        BN_free(pri_key_bn);
        return NULL;
    }

    BN_free(pri_key_bn);
    return pkey;
}

EVP_PKEY* ec_pub_key(int curveNID, const uint8_t* pub_key, size_t pub_key_len) {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(curveNID);
    if (!ec_key) return NULL;

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *pub_point = EC_POINT_new(group);
    if (!pub_point || !EC_POINT_oct2point(group, pub_point, pub_key, pub_key_len, NULL)
            || !EC_KEY_set_public_key(ec_key, pub_point)) {
        EC_KEY_free(ec_key);
        EC_POINT_free(pub_point);
        return NULL;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || !EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        EC_POINT_free(pub_point);
        return NULL;
    }

    EC_POINT_free(pub_point);
    return pkey;
}

BIGNUM* ec_pri_key_bn(const EC_GROUP* group, const uint8_t* pri_key_bytes) {
    int pri_key_len = ec_pri_key_len(group);
    if (pri_key_len == OPENSSL_FAILURE) {
        return NULL;
    }

    BIGNUM* pri_key = BN_new();
    if (pri_key == NULL) {
        return NULL;
    }

    if (BN_bin2bn(pri_key_bytes, pri_key_len, pri_key) == NULL) {
        OPENSSL_print_err();

        return NULL;
    }

    return pri_key;
}

EC_POINT* ec_pub_key_point(const EC_GROUP* group, const uint8_t* pub_key_bytes, const size_t pub_key_len) {
    EC_POINT* pub_point = EC_POINT_new(group);
    if (pub_point == NULL) {
        return NULL;
    }

    if(!EC_POINT_oct2point(group, pub_point, pub_key_bytes, pub_key_len, NULL)) {
        OPENSSL_print_err();

        return NULL;
    }

    return pub_point;
}

int ec_check_point_order(const EC_GROUP* group, const EC_POINT *point) {
    BIGNUM* order = BN_new();
    if (order == NULL) {
        return OPENSSL_FAILURE;
    }

    if (!EC_GROUP_get_order(group, order, NULL)) {
        OPENSSL_print_err();
        BN_free(order);

        return OPENSSL_FAILURE;
    }

    EC_POINT* product = EC_POINT_new(group);
    if (product == NULL) {
        OPENSSL_print_err();
        BN_free(order);

        return OPENSSL_FAILURE;
    }

    if (!EC_POINT_mul(group, product, NULL, point, order, NULL)) {
        OPENSSL_print_err();
        BN_free(order);
        EC_POINT_free(product);

        return OPENSSL_FAILURE;
    }

    if (!EC_POINT_is_at_infinity(group, product)) {
        OPENSSL_print_err();
        BN_free(order);
        EC_POINT_free(product);

        return OPENSSL_FAILURE;
    }

    BN_free(order);
    EC_POINT_free(product);

    return OPENSSL_SUCCESS;
}

int ec_validate_point(EC_GROUP* group, EC_POINT *point) {
    return EC_POINT_is_on_curve(group, point, NULL) &&
           ec_check_point_order(group, point);
}

EVP_PKEY_CTX* ec_create_pkey_ctx(EVP_PKEY* pkey) {
    EVP_PKEY_CTX* ctx = NULL;

    if (pkey != NULL) {
        ctx = EVP_PKEY_CTX_new(pkey, NULL);
    } else {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    }

    if (ctx == NULL) {
        OPENSSL_print_err();

        return NULL;
    }

    return ctx;
}
