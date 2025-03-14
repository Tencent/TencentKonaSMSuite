/*
 * Copyright (C) 2024, 2025, THL A29 Limited, a Tencent company. All rights reserved.
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

ECDSA_CTX* ecdsa_create_ctx(int md_nid, EC_KEY* key) {
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        OPENSSL_print_err();

        return NULL;
    }

    const EVP_MD* md = EVP_get_digestbynid(md_nid);
    if (md == NULL) {
        OPENSSL_print_err();
        EVP_MD_CTX_free(mctx);
        return NULL;
    }
    EVP_DigestInit_ex(mctx, md, NULL);

    ECDSA_CTX* ctx = OPENSSL_malloc(sizeof(ECDSA_CTX));
    if (ctx == NULL) {
        OPENSSL_print_err();
        EVP_MD_CTX_free(mctx);
        return NULL;
    }

    ctx->mctx = mctx;
    ctx->key = key;

    return ctx;
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecdsaCreateCtx
  (JNIEnv* env, jclass classObj, jint mdNID, jint curveNID, jbyteArray key, jboolean isSign) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(curveNID);
    if (group == NULL) {
        return OPENSSL_FAILURE;
    }

    int key_len = (*env)->GetArrayLength(env, key);
    if (key_len < (isSign ? PRI_KEY_MIN_LEN : PUB_KEY_MIN_LEN)) {
        EC_GROUP_free(group);

        return OPENSSL_FAILURE;
    }
    jbyte* key_bytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (key_bytes == NULL) {
        EC_GROUP_free(group);

        return OPENSSL_FAILURE;
    }

    EC_KEY* ec_key = NULL;
    if (isSign) {
        ec_key = ec_pri_key_new(curveNID, (const uint8_t *) key_bytes, key_len);
    } else {
        ec_key = ec_pub_key_new(curveNID, (const uint8_t *) key_bytes, key_len);
    }

    (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
    EC_GROUP_free(group);

    ECDSA_CTX* ctx = ecdsa_create_ctx(mdNID, ec_key);
    if (ctx == NULL) {
        return OPENSSL_FAILURE;
    }

    return (jlong)ctx;
}

void ECDSA_CTX_free(ECDSA_CTX* ctx) {
    if (ctx != NULL) {
        if (ctx->mctx != NULL) {
            EVP_MD_CTX_free(ctx->mctx);
            ctx->mctx = NULL;
        }
        if (ctx->key != NULL) {
            EC_KEY_free(ctx->key);
            ctx->key = NULL;
        }

        OPENSSL_free(ctx);
    }
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecdsaFreeCtx
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    ECDSA_CTX_free((ECDSA_CTX*)pointer);
}

uint8_t* ecdsa_sign(ECDSA_CTX* ctx, const uint8_t* msg, size_t msg_len, size_t* sig_len) {
    if (ctx == NULL || msg == NULL || sig_len == NULL) {
        return NULL;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    if (!EVP_DigestUpdate(ctx->mctx, msg, msg_len)) {
        return NULL;
    }
    if (!EVP_DigestFinal_ex(ctx->mctx, digest, &digest_len)) {
        return NULL;
    }
    EVP_DigestInit_ex(ctx->mctx, NULL, NULL);

    ECDSA_SIG* signature = ECDSA_do_sign(digest, digest_len, ctx->key);
    if (signature == NULL) {
        return NULL;
    }

    uint8_t* sig_buf = NULL;
    *sig_len = i2d_ECDSA_SIG(signature, &sig_buf);
    ECDSA_SIG_free(signature);

    if (*sig_len <= 0) {
        OPENSSL_free(sig_buf);
        return NULL;
    }

    return sig_buf;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecdsaSign
  (JNIEnv* env, jobject thisObj, jlong pointer, jbyteArray message) {
    ECDSA_CTX* ctx = (ECDSA_CTX*)pointer;
    if (ctx == NULL) {
        return NULL;
    }

    jsize msg_len = (*env)->GetArrayLength(env, message);
    if (msg_len < 0) {
        return NULL;
    }
    jbyte* msg_bytes = (*env)->GetByteArrayElements(env, message, NULL);
    if (msg_bytes == NULL) {
        return NULL;
    }

    size_t sig_len = 0;
    uint8_t* sig_buf = ecdsa_sign(ctx, (uint8_t*)msg_bytes, msg_len, &sig_len);
    (*env)->ReleaseByteArrayElements(env, message, msg_bytes, JNI_ABORT);

    if (sig_buf == NULL) {
        return NULL;
    }

    jbyteArray sig_bytes = (*env)->NewByteArray(env, sig_len);
    if (sig_bytes == NULL) {
        OPENSSL_free(sig_buf);

        return NULL;
    }

    (*env)->SetByteArrayRegion(env, sig_bytes, 0, sig_len, (jbyte*)sig_buf);
    OPENSSL_free(sig_buf);

    return sig_bytes;
}

int ecdsa_verify(ECDSA_CTX* ctx, const uint8_t* msg, size_t msg_len, const uint8_t* sig, size_t sig_len) {
    if (ctx == NULL || msg == NULL || sig == NULL) {
        return OPENSSL_FAILURE;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    if (!EVP_DigestUpdate(ctx->mctx, msg, msg_len)) {
        return OPENSSL_FAILURE;
    }
    if (!EVP_DigestFinal_ex(ctx->mctx, digest, &digest_len)) {
        return OPENSSL_FAILURE;
    }
    EVP_DigestInit_ex(ctx->mctx, NULL, NULL);

    const unsigned char* p = sig;
    ECDSA_SIG* signature = d2i_ECDSA_SIG(NULL, &p, sig_len);
    if (signature == NULL) {
        return OPENSSL_FAILURE;
    }

    int verify_status = ECDSA_do_verify(digest, digest_len, signature, ctx->key);
    ECDSA_SIG_free(signature);

    return verify_status;
}

JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecdsaVerify
  (JNIEnv* env, jobject thisObj, jlong pointer, jbyteArray message, jbyteArray signature) {
    ECDSA_CTX* ctx = (ECDSA_CTX*)pointer;
    if (ctx == NULL) {
        return OPENSSL_FAILURE;
    }

    jsize msg_len = (*env)->GetArrayLength(env, message);
    jbyte* msg_bytes = (*env)->GetByteArrayElements(env, message, NULL);
    if (msg_bytes == NULL) {
        return OPENSSL_FAILURE;
    }

    jsize sig_len = (*env)->GetArrayLength(env, signature);
    jbyte* sig_bytes = (*env)->GetByteArrayElements(env, signature, NULL);
    if (sig_bytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, message, msg_bytes, JNI_ABORT);

        return OPENSSL_FAILURE;
    }

    int verified = ecdsa_verify(ctx, (uint8_t*)msg_bytes, msg_len, (uint8_t*)sig_bytes, sig_len)
                   ? OPENSSL_SUCCESS : OPENSSL_FAILURE;

    (*env)->ReleaseByteArrayElements(env, message, msg_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, sig_bytes, JNI_ABORT);

    return verified;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecdsaOneShotSign
  (JNIEnv* env, jclass classObj, jint mdNID, jint curveNID, jbyteArray key, jbyteArray message) {
    int key_len = (*env)->GetArrayLength(env, key);
    if (key_len < PRI_KEY_MIN_LEN) {
        return NULL;
    }
    jbyte* key_bytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (key_bytes == NULL) {
        return NULL;
    }

    EC_KEY* ec_key = ec_pri_key_new(curveNID, (const uint8_t *) key_bytes, key_len);
    (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
    if (ec_key == NULL) {
        return NULL;
    }

    ECDSA_CTX* ctx = ecdsa_create_ctx(mdNID, ec_key);
    if (ctx == NULL) {
        EC_KEY_free(ec_key);

        return NULL;
    }

    jsize msg_len = (*env)->GetArrayLength(env, message);
    if (msg_len < 0) {
        ECDSA_CTX_free(ctx);
        return NULL;
    }
    jbyte* msg_bytes = (*env)->GetByteArrayElements(env, message, NULL);
    if (msg_bytes == NULL) {
        ECDSA_CTX_free(ctx);
        return NULL;
    }

    size_t sig_len = 0;
    uint8_t* sig_buf = ecdsa_sign(ctx, (uint8_t*)msg_bytes, msg_len, &sig_len);
    (*env)->ReleaseByteArrayElements(env, message, msg_bytes, JNI_ABORT);

    if (sig_buf == NULL) {
        ECDSA_CTX_free(ctx);
        return NULL;
    }

    jbyteArray sig_bytes = (*env)->NewByteArray(env, sig_len);
    if (sig_bytes == NULL) {
        OPENSSL_free(sig_buf);
        ECDSA_CTX_free(ctx);
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, sig_bytes, 0, sig_len, (jbyte*)sig_buf);
    OPENSSL_free(sig_buf);
    ECDSA_CTX_free(ctx);

    return sig_bytes;
}

JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecdsaOneShotVerify
  (JNIEnv* env, jclass classObj, jint mdNID, jint curveNID, jbyteArray key, jbyteArray message, jbyteArray signature) {
    int key_len = (*env)->GetArrayLength(env, key);
    if (key_len <= 0) {
        return OPENSSL_FAILURE;
    }
    jbyte* key_bytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (key_bytes == NULL) {
        return OPENSSL_FAILURE;
    }

    EC_KEY* ec_key = ec_pub_key_new(curveNID, (const uint8_t *) key_bytes, key_len);
    (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
    if (ec_key == NULL) {
        return OPENSSL_FAILURE;
    }

    ECDSA_CTX* ctx = ecdsa_create_ctx(mdNID, ec_key);
    if (ctx == NULL) {
        EC_KEY_free(ec_key);
        return OPENSSL_FAILURE;
    }

    jsize msg_len = (*env)->GetArrayLength(env, message);
    jbyte* msg_bytes = (*env)->GetByteArrayElements(env, message, NULL);
    if (msg_bytes == NULL) {
        ECDSA_CTX_free(ctx);
        return OPENSSL_FAILURE;
    }

    jsize sig_len = (*env)->GetArrayLength(env, signature);
    jbyte* sig_bytes = (*env)->GetByteArrayElements(env, signature, NULL);
    if (sig_bytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, message, msg_bytes, JNI_ABORT);
        ECDSA_CTX_free(ctx);
        return OPENSSL_FAILURE;
    }

    int verified = ecdsa_verify(ctx, (uint8_t*)msg_bytes, msg_len, (uint8_t*)sig_bytes, sig_len)
                   ? OPENSSL_SUCCESS : OPENSSL_FAILURE;

    (*env)->ReleaseByteArrayElements(env, message, msg_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, sig_bytes, JNI_ABORT);

    ECDSA_CTX_free(ctx);

    return verified;
}
