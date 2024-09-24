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

#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <jni.h>
#include "kona_crypto.h"

#define SM3_DIGEST_LEN       32
#define SM3_MAC_LEN          32
#define SM4_KEY_LEN          16
#define SM4_GCM_TAG_LEN      16

#define KONA_GOOD             0
#define KONA_BAD             -1

void print_hex(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/* ***** SM3 start ***** */
int sm3_reset(EVP_MD_CTX *ctx) {
    if(!EVP_MD_CTX_reset(ctx)) {
        return KONA_BAD;
    }

    const EVP_MD *md = EVP_sm3();
    if (!EVP_DigestInit_ex(ctx, md, NULL)) {
        return KONA_BAD;
    }

    return KONA_GOOD;
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3CreateCtx
  (JNIEnv *env, jobject thisObj) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return KONA_BAD;
    }

    const EVP_MD *md = EVP_sm3();
    if (!EVP_DigestInit_ex(ctx, md, NULL)) {
        return KONA_BAD;
    }

    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3FreeCtx
  (JNIEnv *env, jobject thisObj, jlong pointer) {
    if (pointer <= 0) {
        return;
    }

    EVP_MD_CTX *ctx = (EVP_MD_CTX *)pointer;
    if (ctx != NULL) {
        EVP_MD_CTX_free(ctx);
    }
}

JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3Update
  (JNIEnv *env, jobject thisObj, jlong pointer, jbyteArray data) {
    if (pointer <= 0 || data == NULL) {
        return KONA_BAD;
    }

    EVP_MD_CTX *ctx = (EVP_MD_CTX *)pointer;
    if (ctx == NULL) {
        return KONA_BAD;
    }

    int data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (data_bytes == NULL) {
        return KONA_BAD;
    }

    int result;
    if (EVP_DigestUpdate(ctx, data_bytes, data_len)) {
        result = KONA_GOOD;
    } else {
        result = KONA_BAD;
    }

    // Clean
    (*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3Final
  (JNIEnv *env, jobject thisObj, jlong pointer) {
    if (pointer <= 0) {
        return NULL;
    }

    EVP_MD_CTX *ctx = (EVP_MD_CTX *)pointer;
    if (ctx == NULL) {
        return NULL;
    }

    unsigned char digest[SM3_DIGEST_LEN];
    unsigned int digest_len = 0;

    if (!EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
        return NULL;
    }

    // Reset the context after generating the digest
    sm3_reset(ctx);

    if (digest_len <= 0) {
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, digest_len);
    if (result == NULL) {
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, result, 0, digest_len, (jbyte *)digest);
    return result;
}

JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3Reset
  (JNIEnv *env, jobject thisObj, jlong pointer) {
    if (pointer <= 0) {
        return KONA_BAD;
    }

    EVP_MD_CTX *ctx = (EVP_MD_CTX *)pointer;
    if (ctx == NULL) {
        return KONA_BAD;
    }

    return sm3_reset(ctx);
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3Clone
  (JNIEnv *env, jobject thisObj, jlong pointer) {
    if (pointer <= 0) {
        return KONA_BAD;
    }

    EVP_MD_CTX *orig_ctx = (EVP_MD_CTX *)pointer;
    if (orig_ctx == NULL) {
        return KONA_BAD;
    }

    EVP_MD_CTX *new_ctx = EVP_MD_CTX_new();
    if (new_ctx == NULL) {
        return KONA_BAD;
    }

    if (!EVP_MD_CTX_copy_ex(new_ctx, orig_ctx)) {
        return KONA_BAD;
    }

    return (jlong)new_ctx;
}
/* ***** SM3 end ***** */

/* ***** SM3HMAC start ***** */
int sm3hmac_reset(EVP_MAC_CTX *ctx) {
    if(!EVP_MAC_init(ctx, NULL, 0, NULL)) {
        return KONA_BAD;
    }

    return KONA_GOOD;
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacCreateCtx
  (JNIEnv *env, jobject thisObj, jbyteArray key) {
    if (key == NULL) {
        return KONA_BAD;
    }

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL) {
        return KONA_BAD;
    }

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        return KONA_BAD;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SM3", 0),
        OSSL_PARAM_construct_end()
    };

    const int key_len = (*env)->GetArrayLength(env, key);
    jbyte *key_bytes = (*env)->GetByteArrayElements(env, key, NULL);
    const EVP_MD *md = EVP_sm3();
    long result;
    if (EVP_MAC_init(ctx, (unsigned char *)key_bytes, key_len, params)) {
        result = (long)ctx;
    } else {
        result = KONA_BAD;
    }

    // Clean
    (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);

    return (jlong)result;
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacFreeCtx
  (JNIEnv *env, jobject thisObj, jlong pointer) {
    if (pointer <= 0) {
        return;
    }

    EVP_MAC_CTX *ctx = (EVP_MAC_CTX *)pointer;
    if (ctx != NULL) {
        EVP_MAC *mac = EVP_MAC_CTX_get0_mac(ctx);
        if (mac != NULL) {
        // TODO
//            EVP_MAC_free(mac);
        }

        EVP_MAC_CTX_free(ctx);
    }
}

JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacUpdate
  (JNIEnv *env, jobject thisObj, jlong pointer, jbyteArray data) {
    if (pointer <= 0 || data == NULL) {
        return KONA_BAD;
    }

    EVP_MAC_CTX *ctx = (EVP_MAC_CTX *)pointer;
    if (ctx == NULL) {
        return KONA_BAD;
    }

    const int data_len = (*env)->GetArrayLength(env, data);
    jbyte *data_bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (data_bytes == NULL) {
        return KONA_BAD;
    }

    int result;
    if (EVP_MAC_update(ctx, (unsigned char *)data_bytes, data_len)) {
        result = KONA_GOOD;
    } else {
        result = KONA_BAD;
    }

    // Clean
    (*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);

    return (jint)result;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacFinal
  (JNIEnv *env, jobject thisObj, jlong pointer) {
    if (pointer <= 0) {
        return NULL;
    }

    EVP_MAC_CTX *ctx = (EVP_MAC_CTX *)pointer;
    if (ctx == NULL) {
        return NULL;
    }

    unsigned char mac[SM3_MAC_LEN];
    size_t mac_len = 0;

    if (!EVP_MAC_final(ctx, mac, &mac_len, sizeof(mac))) {
        return NULL;
    }

    // Reset the context after generating the mac
    sm3hmac_reset(ctx);

    if (mac_len <= 0) {
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, mac_len);
    if (result == NULL) {
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, result, 0, mac_len, (jbyte *)mac);
    return result;
}

JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacReset
  (JNIEnv *env, jobject thisObj, jlong pointer) {
    if (pointer <= 0) {
        return KONA_BAD;
    }

    EVP_MAC_CTX *ctx = (EVP_MAC_CTX *)pointer;
    if (ctx == NULL) {
        return KONA_BAD;
    }

    return sm3hmac_reset(ctx);
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3hmacClone
  (JNIEnv *env, jobject thisObj, jlong pointer) {
    if (pointer <= 0) {
        return KONA_BAD;
    }

    EVP_MAC_CTX *orig_ctx = (EVP_MAC_CTX *)pointer;
    if (orig_ctx == NULL) {
        return KONA_BAD;
    }

    EVP_MAC_CTX *new_ctx = EVP_MAC_CTX_dup(orig_ctx);
    if (new_ctx == NULL) {
        return KONA_BAD;
    }

    return (jlong)new_ctx;
}
/* ***** SM3HMAC end ***** */
