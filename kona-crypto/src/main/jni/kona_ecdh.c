/*
 * Copyright (C) 2025, Tencent. All rights reserved.
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

#include <stdbool.h>
#include <string.h>

#include <jni.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "kona/kona_jni.h"
#include "kona/kona_common.h"
#include "kona/kona_ec.h"

ECDH_CTX* ecdh_create_ctx(int curve_nid, EC_KEY* pri_key) {
    if (pri_key == NULL) {
        return NULL;
    }

    ECDH_CTX* ctx = (ECDH_CTX*)OPENSSL_malloc(sizeof(ECDH_CTX));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->curve_nid = curve_nid;
    const EC_GROUP* group = EC_KEY_get0_group(pri_key);
    ctx->key_len = ec_pri_key_len(group);
    ctx->pri_key = pri_key;

    return ctx;
}

void ecdh_ctx_free(ECDH_CTX* ctx) {
    if (ctx != NULL) {
        if (ctx->pri_key != NULL) {
            EC_KEY_free(ctx->pri_key);
            ctx->pri_key = NULL;
        }

        OPENSSL_free(ctx);
    }
}

uint8_t* ecdh_derive(ECDH_CTX* ctx, const EC_POINT* peer_pub_point) {
    if (!ctx || !peer_pub_point) {
        return NULL;
    }

    unsigned char* shared_key = OPENSSL_malloc(ctx->key_len);
    if (!shared_key) {
        return NULL;
    }

    int shared_key_len = ECDH_compute_key(shared_key, ctx->key_len, peer_pub_point, ctx->pri_key, NULL);
    if (shared_key_len == 0 || shared_key_len != ctx->key_len) {
        OPENSSL_free(shared_key);

        return NULL;
    }

    return shared_key;
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecdhCreateCtx
  (JNIEnv* env, jclass classObj, jint curveNID, jbyteArray priKey) {
    int key_len = (*env)->GetArrayLength(env, priKey);
    if (key_len <= 0) {
        return OPENSSL_FAILURE;
    }
    jbyte* pri_key_bytes = (*env)->GetByteArrayElements(env, priKey, NULL);
    if (pri_key_bytes == NULL) {
        return OPENSSL_FAILURE;
    }

    EC_KEY* pri_key = ec_pri_key_new(curveNID, (const uint8_t *) pri_key_bytes,
                                     key_len);
    (*env)->ReleaseByteArrayElements(env, priKey, pri_key_bytes, JNI_ABORT);
    if (pri_key == NULL) {
        return OPENSSL_FAILURE;
    }

    ECDH_CTX* ctx = ecdh_create_ctx(curveNID, pri_key);
    if (ctx == NULL) {
        EC_KEY_free(pri_key);

        return OPENSSL_FAILURE;
    }

    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecdhFreeCtx
  (JNIEnv* env, jclass classObj, jlong pointer) {
    ecdh_ctx_free((ECDH_CTX *) pointer);
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecdhDeriveKey
  (JNIEnv* env, jclass classObj, jlong pointer, jbyteArray peerPubKey) {
    ECDH_CTX* ctx = (ECDH_CTX*)pointer;
    if (ctx == NULL) {
        return NULL;
    }

    jsize peer_pub_key_len = (*env)->GetArrayLength(env, peerPubKey);
    if (peer_pub_key_len <= 0) {
        return NULL;
    }
    jbyte* peer_pub_key_bytes = (*env)->GetByteArrayElements(env, peerPubKey, NULL);
    if (peer_pub_key_bytes == NULL) {
        return NULL;
    }

    EC_KEY* peer_pub_key = ec_pub_key_new(ctx->curve_nid,
                                          (const uint8_t *) peer_pub_key_bytes,
                                          peer_pub_key_len);
    (*env)->ReleaseByteArrayElements(env, peerPubKey, peer_pub_key_bytes, JNI_ABORT);
    if (peer_pub_key == NULL) {
        return NULL;
    }

    const EC_POINT* peer_pub_point = EC_KEY_get0_public_key(peer_pub_key);
    if (peer_pub_point == NULL) {
        return NULL;
    }


    uint8_t* shared_key = ecdh_derive(ctx, peer_pub_point);
    EC_KEY_free(peer_pub_key);
    if (shared_key == NULL) {
        return NULL;
    }

    jbyteArray shared_key_bytes = (*env)->NewByteArray(env, ctx->key_len);
    if (shared_key_bytes != NULL) {
        (*env)->SetByteArrayRegion(env, shared_key_bytes, 0, ctx->key_len, (jbyte*)shared_key);
    }

    OPENSSL_free(shared_key);

    return shared_key_bytes;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecdhOneShotDeriveKey
  (JNIEnv* env, jclass classObj, jint curveNID, jbyteArray priKey, jbyteArray peerPubKey) {
    int key_len = (*env)->GetArrayLength(env, priKey);
    if (key_len <= 0) {
        return NULL;
    }
    jbyte* pri_key_bytes = (*env)->GetByteArrayElements(env, priKey, NULL);
    if (pri_key_bytes == NULL) {
        return NULL;
    }

    EC_KEY* pri_key = ec_pri_key_new(curveNID, (const uint8_t *) pri_key_bytes,
                                     key_len);
    (*env)->ReleaseByteArrayElements(env, priKey, pri_key_bytes, JNI_ABORT);
    if (pri_key == NULL) {
        return NULL;
    }

    ECDH_CTX* ctx = ecdh_create_ctx(curveNID, pri_key);
    if (ctx == NULL) {
        EC_KEY_free(pri_key);

        return NULL;
    }

    jsize peer_pub_key_len = (*env)->GetArrayLength(env, peerPubKey);
    if (peer_pub_key_len <= 0) {
        ecdh_ctx_free(ctx);
        return NULL;
    }
    jbyte* peer_pub_key_bytes = (*env)->GetByteArrayElements(env, peerPubKey, NULL);
    if (peer_pub_key_bytes == NULL) {
        ecdh_ctx_free(ctx);

        return NULL;
    }

    EC_KEY* peer_pub_key = ec_pub_key_new(ctx->curve_nid,
                                          (const uint8_t *) peer_pub_key_bytes,
                                          peer_pub_key_len);
    (*env)->ReleaseByteArrayElements(env, peerPubKey, peer_pub_key_bytes, JNI_ABORT);
    if (peer_pub_key == NULL) {
        ecdh_ctx_free(ctx);

        return NULL;
    }

    const EC_POINT* peer_pub_point = EC_KEY_get0_public_key(peer_pub_key);
    if (peer_pub_point == NULL) {
        ecdh_ctx_free(ctx);
        EC_KEY_free(peer_pub_key);

        return NULL;
    }

    uint8_t* shared_key = ecdh_derive(ctx, peer_pub_point);
    EC_KEY_free(peer_pub_key);
    if (shared_key == NULL) {
        ecdh_ctx_free(ctx);

        return NULL;
    }

    jbyteArray shared_key_bytes = (*env)->NewByteArray(env, ctx->key_len);
    if (shared_key_bytes != NULL) {
        (*env)->SetByteArrayRegion(env, shared_key_bytes, 0, ctx->key_len, (jbyte*)shared_key);
    }

    OPENSSL_free(shared_key);
    ecdh_ctx_free(ctx);

    return shared_key_bytes;
}
