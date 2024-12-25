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

#include <jni.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "kona/kona_common.h"
#include "kona/kona_sm2.h"

const uint8_t ID[] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

const SM2_ID* sm2_id() {
    static const SM2_ID* sm2_id = NULL;

    if (sm2_id == NULL) {
        SM2_ID* id = OPENSSL_malloc(sizeof(SM2_ID));
        id->id = ID;
        id->id_len = sizeof(ID);

        sm2_id = id;
    }

    return sm2_id;
}

const uint8_t FIELD[] = {
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

const uint8_t ORDER[] = {
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B,
        0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23
};

const uint8_t A[] = {
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};

const uint8_t B[] = {
        0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
        0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
        0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
        0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93
};

const uint8_t GEN_X[] = {
        0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
        0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
        0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
        0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7
};

const uint8_t GEN_Y[] = {
        0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
        0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
        0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
        0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0
};

const SM2_CURVE* sm2_curve() {
    static const SM2_CURVE* sm2_curve = NULL;

    if (sm2_curve == NULL) {
        SM2_CURVE* curve = OPENSSL_malloc(sizeof(SM2_CURVE));
        curve->field = FIELD;
        curve->field_len = sizeof(FIELD);
        curve->order = ORDER;
        curve->order_len = sizeof(ORDER);
        curve->a = A;
        curve->a_len = sizeof(A);
        curve->b = B;
        curve->b_len = sizeof(B);
        curve->gen_x = GEN_X;
        curve->gen_x_len = sizeof(GEN_X);
        curve->gen_y = GEN_Y;
        curve->gen_y_len = sizeof(GEN_Y);

        sm2_curve = curve;
    }

    return sm2_curve;
}

const EC_GROUP* sm2_group() {
    static const EC_GROUP* sm2_group = NULL;

    if (sm2_group == NULL) {
        EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);
        if (group == NULL) {
            return NULL;
        }
        sm2_group = group;
    }

    return sm2_group;
}

BIGNUM* sm2_pri_key(const uint8_t* pri_key_bytes) {
    BIGNUM* pri_key = BN_new();
    if (pri_key == NULL) {
        return NULL;
    }

    if (BN_bin2bn(pri_key_bytes, 32, pri_key) == NULL) {
        return NULL;
    }

    return pri_key;
}

EC_POINT* sm2_pub_key(const uint8_t* pub_key_bytes, const size_t pub_key_len) {
    const EC_GROUP* group = sm2_group();

    EC_POINT* pub_key = EC_POINT_new(group);
    if (pub_key == NULL) {
        return NULL;
    }

    if(!EC_POINT_oct2point(group, pub_key, pub_key_bytes, pub_key_len, NULL)) {
        return NULL;
    }

    return pub_key;
}

int sm2_check_point_order(const EC_GROUP* group, const EC_POINT *point) {
    BIGNUM* order = BN_new();
    if (order == NULL) {
        return OPENSSL_FAILURE;
    }

    if (!EC_GROUP_get_order(group, order, NULL)) {
        BN_free(order);

        return OPENSSL_FAILURE;
    }

    EC_POINT* product = EC_POINT_new(group);
    if (product == NULL) {
        BN_free(order);

        return OPENSSL_FAILURE;
    }

    if (!EC_POINT_mul(group, product, NULL, point, order, NULL)) {
        BN_free(order);
        EC_POINT_free(product);

        return OPENSSL_FAILURE;
    }

    if (!EC_POINT_is_at_infinity(group, product)) {
        BN_free(order);
        EC_POINT_free(product);

        return OPENSSL_FAILURE;
    }

    BN_free(order);
    EC_POINT_free(product);

    return OPENSSL_SUCCESS;
}

int sm2_validate_point(EC_POINT *point) {
    return EC_POINT_is_on_curve(sm2_group(), point, NULL) &&
           sm2_check_point_order(sm2_group(), point);
}

EVP_PKEY* sm2_load_pub_key(const uint8_t* pub_key, size_t pub_key_len) {
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

EVP_PKEY* sm2_load_key_pair(const uint8_t* pri_key, const uint8_t* pub_key) {
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
    ec_key = NULL; // ec_key cannot be freed due to pkey is using it.

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
