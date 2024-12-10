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

#include "kona/kona_jni.h"
#include "kona/kona_common.h"
#include "kona/kona_sm2.h"

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2ToUncompPubKey
  (JNIEnv* env, jobject thisObj, jbyteArray compPubKey) {
    jsize comp_pub_key_len = (*env)->GetArrayLength(env, compPubKey);
    if (comp_pub_key_len != SM2_COMP_PUB_KEY_LEN) {
        return NULL;
    }
    jbyte* comp_pub_key_bytes = (*env)->GetByteArrayElements(env, compPubKey, NULL);
    if (comp_pub_key_bytes == NULL) {
        return NULL;
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (group == NULL) {
        OPENSSL_print_err();
        (*env)->ReleaseByteArrayElements(env, compPubKey, comp_pub_key_bytes, JNI_ABORT);
        return NULL;
    }

    EC_POINT* point = EC_POINT_new(group);
    if (point == NULL) {
        OPENSSL_print_err();
        (*env)->ReleaseByteArrayElements(env, compPubKey, comp_pub_key_bytes, JNI_ABORT);
        EC_GROUP_free(group);
        return NULL;
    }

    // Convert the compressed public key to an EC_POINT
    if (!EC_POINT_oct2point(group, point, (uint8_t*)comp_pub_key_bytes, comp_pub_key_len, NULL)) {
        OPENSSL_print_err();
        (*env)->ReleaseByteArrayElements(env, compPubKey, comp_pub_key_bytes, JNI_ABORT);
        EC_GROUP_free(group);
        EC_POINT_free(point);
        return NULL;
    }

    // Convert the EC_POINT to an uncompressed public key
    uint8_t uncomp_pub_key[SM2_PUB_KEY_LEN];
    size_t uncomp_pub_key_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, uncomp_pub_key, SM2_PUB_KEY_LEN, NULL);
    if (uncomp_pub_key_len <= 0) {
        OPENSSL_print_err();
        (*env)->ReleaseByteArrayElements(env, compPubKey, comp_pub_key_bytes, JNI_ABORT);
        EC_GROUP_free(group);
        EC_POINT_free(point);
        return NULL;
    }

    (*env)->ReleaseByteArrayElements(env, compPubKey, comp_pub_key_bytes, JNI_ABORT);
    EC_GROUP_free(group);
    EC_POINT_free(point);

    jbyteArray uncompPubKey = (*env)->NewByteArray(env, uncomp_pub_key_len);
    if (uncompPubKey == NULL) {
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, uncompPubKey, 0, uncomp_pub_key_len, (jbyte*)uncomp_pub_key);

    return uncompPubKey;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2GenPubKey
  (JNIEnv* env, jobject thisObj, jbyteArray priKey) {
    jsize pri_key_len = (*env)->GetArrayLength(env, priKey);
    if (pri_key_len != SM2_PRI_KEY_LEN) {
        return NULL;
    }
    jbyte* pri_key_bytes = (*env)->GetByteArrayElements(env, priKey, NULL);
    if (pri_key_bytes == NULL) {
        return NULL;
    }

    uint8_t pub_key_buf[SM2_PUB_KEY_LEN];
    if (!sm2_gen_pub_key((const uint8_t*)pri_key_bytes, pub_key_buf)) {
        (*env)->ReleaseByteArrayElements(env, priKey, pri_key_bytes, JNI_ABORT);
        return NULL;
    }
    (*env)->ReleaseByteArrayElements(env, priKey, pri_key_bytes, JNI_ABORT);

    jbyteArray pubKey = (*env)->NewByteArray(env, SM2_PUB_KEY_LEN);
    if (pubKey == NULL) {
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, pubKey, 0, SM2_PUB_KEY_LEN, (jbyte*)pub_key_buf);

    return pubKey;
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2KeyPairGenCreateCtx
  (JNIEnv* env, jobject thisObj) {
    EVP_PKEY_CTX* ctx = sm2_create_pkey_ctx(NULL);
    return ctx == NULL ? OPENSSL_FAILURE : (jlong)ctx;
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2KeyPairGenFreeCtx
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    EVP_PKEY_CTX* ctx = (EVP_PKEY_CTX*)pointer;
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
}

int sm2_gen_key_pair(EVP_PKEY_CTX* ctx, uint8_t* key_pair, size_t* key_pair_len) {
    if (ctx == NULL) {
        return OPENSSL_FAILURE;
    }

    if (!EVP_PKEY_keygen_init(ctx)) {
        OPENSSL_print_err();
        return OPENSSL_FAILURE;
    }

    EVP_PKEY* pkey = NULL;
    if (!EVP_PKEY_keygen(ctx, &pkey)) {
        OPENSSL_print_err();
        return OPENSSL_FAILURE;
    }

    BIGNUM* priv_key_bn = NULL;
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_key_bn)) {
        OPENSSL_print_err();
        EVP_PKEY_free(pkey);
        return OPENSSL_FAILURE;
    }
    if (BN_num_bytes(priv_key_bn) > SM2_PRI_KEY_LEN) {
        EVP_PKEY_free(pkey);
        BN_free(priv_key_bn);
        return OPENSSL_FAILURE;
    }
    uint8_t priv_key_buf[SM2_PRI_KEY_LEN] = {0};
    BN_bn2binpad(priv_key_bn, priv_key_buf, SM2_PRI_KEY_LEN);
    BN_free(priv_key_bn);

    size_t pub_key_len = 0;
    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_key_len)) {
        OPENSSL_print_err();
        EVP_PKEY_free(pkey);
        OPENSSL_cleanse(priv_key_buf, SM2_PRI_KEY_LEN);
        return OPENSSL_FAILURE;
    }
    uint8_t* pub_key_buf = OPENSSL_malloc(pub_key_len);
    if (pub_key_buf == NULL) {
        EVP_PKEY_free(pkey);
        OPENSSL_cleanse(priv_key_buf, SM2_PRI_KEY_LEN);
        return OPENSSL_FAILURE;
    }

    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub_key_buf, pub_key_len, &pub_key_len)) {
        OPENSSL_print_err();
        EVP_PKEY_free(pkey);
        OPENSSL_cleanse(priv_key_buf, SM2_PRI_KEY_LEN);
        OPENSSL_free(pub_key_buf);
        return OPENSSL_FAILURE;
    }

    *key_pair_len = SM2_PRI_KEY_LEN + pub_key_len;
    memcpy(key_pair, priv_key_buf, SM2_PRI_KEY_LEN);
    memcpy(key_pair + SM2_PRI_KEY_LEN, pub_key_buf, pub_key_len);

    EVP_PKEY_free(pkey);
    OPENSSL_cleanse(priv_key_buf, SM2_PRI_KEY_LEN);
    OPENSSL_free(pub_key_buf);

    return OPENSSL_SUCCESS;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2KeyPairGenGenKeyPair
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    EVP_PKEY_CTX* ctx = (EVP_PKEY_CTX*)pointer;
    if (ctx == NULL) {
        return NULL;
    }

    size_t key_pair_len = SM2_PRI_KEY_LEN + SM2_PUB_KEY_LEN;
    uint8_t* key_pair_buf = OPENSSL_malloc(key_pair_len);
    if (key_pair_buf == NULL) {
        return NULL;
    }

    if (!sm2_gen_key_pair(ctx, key_pair_buf, &key_pair_len)) {
        OPENSSL_free(key_pair_buf);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, key_pair_len);
    if (result) {
        jbyte* result_bytes = (*env)->GetByteArrayElements(env, result, NULL);

        if (result_bytes) {
            memcpy(result_bytes, key_pair_buf, key_pair_len);
            (*env)->ReleaseByteArrayElements(env, result, result_bytes, 0);
        } else {
            (*env)->DeleteLocalRef(env, result);
            result = NULL;
        }
    }

    OPENSSL_free(key_pair_buf);

    return result;
}
