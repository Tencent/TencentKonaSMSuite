/*
 * Copyright (C) 2025, 2026, Tencent. All rights reserved.
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

// Need to use the deprecated lower EC functions
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>

#include <jni.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

#include "kona/kona_common.h"
#include "kona/kona_jni.h"
#include "kona/kona_ec.h"

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecOneShotKeyPairGenGenKeyPair
  (JNIEnv* env, jclass classObj, jint curveNID, jbyteArray priKey, jbyteArray pubKey) {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(curveNID);
    if (ec_key == NULL) {
        OPENSSL_print_err();

        return;
    }

    if (!EC_KEY_generate_key(ec_key)) {
        OPENSSL_print_err();
        EC_KEY_free(ec_key);

        return;
    }

    const EC_GROUP* group = EC_KEY_get0_group(ec_key);

    const BIGNUM* pri_key_bn = EC_KEY_get0_private_key(ec_key);
    jsize priv_key_len = (*env)->GetArrayLength(env, priKey);
    // Encode the private key into a native buffer, then copy it out to the Java
    // array with SetByteArrayRegion. The native buffer is scrubbed with
    // OPENSSL_clear_free rather than using GetPrimitiveArrayCritical, which
    // would write directly into the Java heap and cannot be safely zeroed.
    uint8_t* priv_key_buf = OPENSSL_malloc(priv_key_len);
    if (priv_key_buf == NULL) {
        OPENSSL_print_err();
        EC_KEY_free(ec_key);
        return;
    }
    if (BN_bn2binpad(pri_key_bn, priv_key_buf, priv_key_len) != priv_key_len) {
        OPENSSL_print_err();
        OPENSSL_clear_free(priv_key_buf, priv_key_len);
        EC_KEY_free(ec_key);
        return;
    }
    (*env)->SetByteArrayRegion(env, priKey, 0, priv_key_len, (jbyte*)priv_key_buf);
    OPENSSL_clear_free(priv_key_buf, priv_key_len);
    if ((*env)->ExceptionCheck(env)) {
        EC_KEY_free(ec_key);
        return;
    }

    const EC_POINT* pub_key_point = EC_KEY_get0_public_key(ec_key);
    jsize pub_key_len = (*env)->GetArrayLength(env, pubKey);
    uint8_t* pub_key_buf = OPENSSL_malloc(pub_key_len);
    if (pub_key_buf == NULL) {
        OPENSSL_print_err();
        EC_KEY_free(ec_key);
        return;
    }
    if (EC_POINT_point2oct(group, pub_key_point, POINT_CONVERSION_UNCOMPRESSED,
                           pub_key_buf, pub_key_len, NULL) != (size_t)pub_key_len) {
        OPENSSL_print_err();
        OPENSSL_free(pub_key_buf);
        EC_KEY_free(ec_key);
        return;
    }
    (*env)->SetByteArrayRegion(env, pubKey, 0, pub_key_len, (jbyte*)pub_key_buf);
    OPENSSL_free(pub_key_buf);
    if ((*env)->ExceptionCheck(env)) {
        EC_KEY_free(ec_key);
        return;
    }

    EC_KEY_free(ec_key);
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecKeyPairGenCreateCtx
  (JNIEnv* env, jclass classObj, jint curveNID) {
    EVP_PKEY_CTX* pctx = ec_create_pkey_ctx(NULL);
    if (pctx == NULL) {
        return 0;
    }

    if (!EVP_PKEY_keygen_init(pctx)) {
        OPENSSL_print_err();
        EVP_PKEY_CTX_free(pctx);

        return 0;
    }

    if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curveNID)) {
        OPENSSL_print_err();
        EVP_PKEY_CTX_free(pctx);

        return 0;
    }

    return (jlong)pctx;
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecKeyPairGenFreeCtx
  (JNIEnv* env, jclass classObj, jlong pointer) {
    EVP_PKEY_CTX* pctx = (EVP_PKEY_CTX*)pointer;
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecKeyPairGenGenKeyPair
  (JNIEnv* env, jclass classObj, jlong pointer, jbyteArray priKey, jbyteArray pubKey) {
    EVP_PKEY_CTX* pctx = (EVP_PKEY_CTX*)pointer;
    if (pctx == NULL) {
        return;
    }

    EVP_PKEY* pkey = NULL;
    if (!EVP_PKEY_keygen(pctx, &pkey)) {
        return;
    }

    const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);

    const BIGNUM* pri_key_bn = EC_KEY_get0_private_key(ec_key);
    jsize priv_key_len = (*env)->GetArrayLength(env, priKey);
    // Encode the private key into a native buffer, then copy it out to the Java
    // array with SetByteArrayRegion. The native buffer is scrubbed with
    // OPENSSL_clear_free rather than using GetPrimitiveArrayCritical, which
    // would write directly into the Java heap and cannot be safely zeroed.
    uint8_t* priv_key_buf = OPENSSL_malloc(priv_key_len);
    if (priv_key_buf == NULL) {
        OPENSSL_print_err();
        EVP_PKEY_free(pkey);
        return;
    }
    if (BN_bn2binpad(pri_key_bn, priv_key_buf, priv_key_len) != priv_key_len) {
        OPENSSL_print_err();
        OPENSSL_clear_free(priv_key_buf, priv_key_len);
        EVP_PKEY_free(pkey);
        return;
    }
    (*env)->SetByteArrayRegion(env, priKey, 0, priv_key_len, (jbyte*)priv_key_buf);
    OPENSSL_clear_free(priv_key_buf, priv_key_len);
    if ((*env)->ExceptionCheck(env)) {
        EVP_PKEY_free(pkey);
        return;
    }

    const EC_POINT* pub_key_point = EC_KEY_get0_public_key(ec_key);
    jsize pub_key_len = (*env)->GetArrayLength(env, pubKey);
    uint8_t* pub_key_buf = OPENSSL_malloc(pub_key_len);
    if (pub_key_buf == NULL) {
        OPENSSL_print_err();
        EVP_PKEY_free(pkey);
        return;
    }
    if (EC_POINT_point2oct(group, pub_key_point, POINT_CONVERSION_UNCOMPRESSED,
                           pub_key_buf, pub_key_len, NULL) != (size_t)pub_key_len) {
        OPENSSL_print_err();
        OPENSSL_free(pub_key_buf);
        EVP_PKEY_free(pkey);
        return;
    }
    (*env)->SetByteArrayRegion(env, pubKey, 0, pub_key_len, (jbyte*)pub_key_buf);
    OPENSSL_free(pub_key_buf);
    if ((*env)->ExceptionCheck(env)) {
        EVP_PKEY_free(pkey);
        return;
    }

    // The private/public keys have been written into the caller-supplied arrays.
    EVP_PKEY_free(pkey);
}
