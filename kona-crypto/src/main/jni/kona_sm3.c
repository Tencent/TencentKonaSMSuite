/*
 * Copyright (C) 2024, 2025, Tencent. All rights reserved.
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

#include <openssl/evp.h>

#include "kona/kona_jni.h"
#include "kona/kona_common.h"
#include "kona/kona_sm3.h"

EVP_MAC* hmac() {
    static EVP_MAC* hmac = NULL;
    if (hmac == NULL) {
        EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        if (mac == NULL) {
            OPENSSL_print_err();
        }
        hmac = mac;
    }

    return hmac;
}

EVP_MD_CTX* sm3_create_ctx() {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        OPENSSL_print_err();

        return NULL;
    }

    const EVP_MD* md = EVP_sm3();
    if (md == NULL) {
        OPENSSL_print_err();

        return NULL;
    }

    if (!EVP_DigestInit_ex(ctx, md, NULL)) {
        OPENSSL_print_err();

        return NULL;
    }

    return ctx;
}

int sm3_reset(EVP_MD_CTX* ctx) {
    if (ctx == NULL) {
        return OPENSSL_FAILURE;
    }

    if (!EVP_DigestInit_ex(ctx, NULL, NULL)) {
        OPENSSL_print_err();

        return OPENSSL_FAILURE;
    }

    return OPENSSL_SUCCESS;
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3CreateCtx
  (JNIEnv* env, jobject thisObj) {
    EVP_MD_CTX* ctx = sm3_create_ctx();

    return ctx == NULL ? OPENSSL_FAILURE : (jlong)ctx;
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3FreeCtx
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    EVP_MD_CTX* ctx = (EVP_MD_CTX*)pointer;
    if (ctx != NULL) {
        EVP_MD_CTX_free(ctx);
    }
}

JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3Update
  (JNIEnv* env, jobject thisObj, jlong pointer, jbyteArray data) {
    EVP_MD_CTX* ctx = (EVP_MD_CTX*)pointer;
    if (ctx == NULL) {
        return OPENSSL_FAILURE;
    }

    if (data == NULL) {
        return OPENSSL_FAILURE;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    if (data_len < 0) {
        return OPENSSL_FAILURE;
    }

    jbyte* data_bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (data_bytes == NULL) {
        return OPENSSL_FAILURE;
    }

    int result;
    if (EVP_DigestUpdate(ctx, data_bytes, data_len)) {
        result = OPENSSL_SUCCESS;
    } else {
        OPENSSL_print_err();

        result = OPENSSL_FAILURE;
    }

    (*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3Final
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    EVP_MD_CTX* ctx = (EVP_MD_CTX*)pointer;
    if (ctx == NULL) {
        return NULL;
    }

    uint8_t digest[SM3_DIGEST_LEN];
    unsigned int digest_len = 0;

    if (!EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
        OPENSSL_print_err();

        return NULL;
    }

    if (!sm3_reset(ctx)) {
        return NULL;
    }

    if (digest_len <= 0) {
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, digest_len);
    if (result == NULL) {
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, result, 0, digest_len, (jbyte*)digest);

    return result;
}

JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3Reset
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    EVP_MD_CTX* ctx = (EVP_MD_CTX*)pointer;
    if (ctx == NULL) {
        return OPENSSL_FAILURE;
    }

    return sm3_reset(ctx);
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3Clone
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    EVP_MD_CTX* orig_ctx = (EVP_MD_CTX*)pointer;
    if (orig_ctx == NULL) {
        return OPENSSL_FAILURE;
    }

    EVP_MD_CTX* new_ctx = EVP_MD_CTX_new();
    if (new_ctx == NULL) {
        return OPENSSL_FAILURE;
    }

    if (!EVP_MD_CTX_copy_ex(new_ctx, orig_ctx)) {
        OPENSSL_print_err();
        EVP_MD_CTX_free(new_ctx);

        return OPENSSL_FAILURE;
    }

    return (jlong)new_ctx;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3OneShotDigest
  (JNIEnv* env, jclass classObj, jbyteArray data) {
    EVP_MD_CTX* ctx = sm3_create_ctx();
    if (ctx == NULL) {
        return NULL;
    }

    if (data == NULL) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    jsize data_len = (*env)->GetArrayLength(env, data);
    if (data_len < 0) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    jbyte* data_bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (data_bytes == NULL) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    if (!EVP_DigestUpdate(ctx, data_bytes, data_len)) {
        (*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    (*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);

    uint8_t digest[SM3_DIGEST_LEN];
    unsigned int digest_len = 0;

    if (!EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    EVP_MD_CTX_free(ctx);

    if (digest_len <= 0) {
        return NULL;
    }

    jbyteArray digest_bytes = (*env)->NewByteArray(env, digest_len);
    if (digest_bytes == NULL) {
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, digest_bytes, 0, digest_len, (jbyte*)digest);

    return digest_bytes;
}

EVP_MAC_CTX* sm3hmac_create_ctx(EVP_MAC* mac, const uint8_t* key, size_t key_len) {
    if (mac == NULL) {
        return OPENSSL_FAILURE;
    }

    if (key == NULL || key_len == 0) {
        return OPENSSL_FAILURE;
    }

    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        OPENSSL_print_err();

        return OPENSSL_FAILURE;
    }

    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("digest", "SM3", 0),
            OSSL_PARAM_construct_end()
    };

    if (!EVP_MAC_init(ctx, key, key_len, params)) {
        OPENSSL_print_err();
        EVP_MAC_CTX_free(ctx);

        return OPENSSL_FAILURE;
    }

    return ctx;
}

int sm3hmac_reset(EVP_MAC_CTX* ctx) {
    if (!EVP_MAC_init(ctx, NULL, 0, NULL)) {
        OPENSSL_print_err();
        return OPENSSL_FAILURE;
    } else {
        return OPENSSL_SUCCESS;
    }
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacCreateCtx
  (JNIEnv* env, jobject thisObj, jbyteArray key) {
    EVP_MAC* mac = hmac();
    if (mac == NULL) {
        return OPENSSL_FAILURE;
    }

    if (key == NULL) {
        return OPENSSL_FAILURE;
    }

    const int key_len = (*env)->GetArrayLength(env, key);
    if (key_len <= 0) {
        return OPENSSL_FAILURE;
    }
    jbyte* key_bytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (key_bytes == NULL) {
        return OPENSSL_FAILURE;
    }

    EVP_MAC_CTX* ctx = sm3hmac_create_ctx(mac, (const uint8_t*)key_bytes, key_len);

    (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);

    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacFreeCtx
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    EVP_MAC_CTX* ctx = (EVP_MAC_CTX*)pointer;
    if (ctx != NULL) {
        EVP_MAC_CTX_free(ctx);
    }
}

JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacUpdate
  (JNIEnv* env, jobject thisObj, jlong pointer, jbyteArray data) {
    EVP_MAC_CTX* ctx = (EVP_MAC_CTX*)pointer;
    if (ctx == NULL) {
        return OPENSSL_FAILURE;
    }

    if (data == NULL) {
        return OPENSSL_FAILURE;
    }

    const int data_len = (*env)->GetArrayLength(env, data);
    jbyte* data_bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (data_bytes == NULL) {
        return OPENSSL_FAILURE;
    }

    int result = OPENSSL_SUCCESS;
    if (!EVP_MAC_update(ctx, (const uint8_t*)data_bytes, data_len)) {
        OPENSSL_print_err();

        result = OPENSSL_FAILURE;
    }

    (*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);

    return (jint)result;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacFinal
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    EVP_MAC_CTX* ctx = (EVP_MAC_CTX*)pointer;
    if (ctx == NULL) {
        return NULL;
    }

    uint8_t mac[SM3_MAC_LEN];
    size_t mac_len = 0;

    if (!EVP_MAC_final(ctx, mac, &mac_len, sizeof(mac))) {
        OPENSSL_print_err();

        return NULL;
    }

    // Reset the context after generating the mac
    if (!sm3hmac_reset(ctx)) {
        return NULL;
    }

    if (mac_len <= 0) {
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, mac_len);
    if (result == NULL) {
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, result, 0, mac_len, (jbyte*)mac);

    return result;
}

JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacReset
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    EVP_MAC_CTX* ctx = (EVP_MAC_CTX*)pointer;
    if (ctx == NULL) {
        return OPENSSL_FAILURE;
    }

    return sm3hmac_reset(ctx);
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacClone
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    EVP_MAC_CTX* orig_ctx = (EVP_MAC_CTX*)pointer;
    if (orig_ctx == NULL) {
        return OPENSSL_FAILURE;
    }

    EVP_MAC_CTX* new_ctx = EVP_MAC_CTX_dup(orig_ctx);
    if (new_ctx == NULL) {
        OPENSSL_print_err();

        return OPENSSL_FAILURE;
    }

    return (jlong)new_ctx;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacOneShotMac
  (JNIEnv* env, jclass classObj, jbyteArray key, jbyteArray data) {
    EVP_MAC* mac = hmac();
    if (mac == NULL) {
        return NULL;
    }

    if (key == NULL) {
        return NULL;
    }

    const int key_len = (*env)->GetArrayLength(env, key);
    if (key_len <= 0) {
        return NULL;
    }
    jbyte* key_bytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (key_bytes == NULL) {
        return NULL;
    }

    EVP_MAC_CTX* ctx = sm3hmac_create_ctx(mac, (const uint8_t*)key_bytes, key_len);

    (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);

    if (ctx == NULL) {
        return NULL;
    }

    if (data == NULL) {
        EVP_MAC_CTX_free(ctx);
        return NULL;
    }

    const int data_len = (*env)->GetArrayLength(env, data);
    jbyte* data_bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (data_bytes == NULL) {
        EVP_MAC_CTX_free(ctx);
        return NULL;
    }

    if (!EVP_MAC_update(ctx, (const uint8_t*)data_bytes, data_len)) {
        (*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);
        EVP_MAC_CTX_free(ctx);
        return NULL;
    }

    (*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);

    uint8_t mac_buf[SM3_MAC_LEN];
    size_t mac_len = 0;

    if (!EVP_MAC_final(ctx, mac_buf, &mac_len, sizeof(mac_buf))) {
        EVP_MAC_CTX_free(ctx);
        return NULL;
    }

    if (mac_len <= 0) {
        EVP_MAC_CTX_free(ctx);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, mac_len);
    if (result == NULL) {
        EVP_MAC_CTX_free(ctx);
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, result, 0, mac_len, (jbyte*)mac_buf);

    EVP_MAC_CTX_free(ctx);

    return result;
}
