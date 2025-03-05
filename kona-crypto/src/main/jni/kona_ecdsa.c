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

#include <stdbool.h>
#include <string.h>

#include <jni.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "kona/kona_jni.h"
#include "kona/kona_common.h"
#include "kona/kona_ec.h"

ECDSA_CTX* ecdsa_create_ctx(int md_nid, EVP_PKEY* pkey, bool is_sign) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL) {
        OPENSSL_print_err();

        return NULL;
    }

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        OPENSSL_print_err();
        EVP_PKEY_CTX_free(pctx);

        return NULL;
    }

    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);

    const EVP_MD* md = EVP_get_digestbynid(md_nid);
    if (md == NULL) {
        OPENSSL_print_err();
        EVP_PKEY_CTX_free(pctx);
        EVP_MD_CTX_free(mctx);
        return NULL;
    }

    if (is_sign) {
        if (!EVP_DigestSignInit(mctx, NULL, md, NULL, pkey)) {
            OPENSSL_print_err();
            EVP_PKEY_CTX_free(pctx);
            EVP_MD_CTX_free(mctx);

            return NULL;
        }
    } else {
        if (!EVP_DigestVerifyInit(mctx, NULL, md, NULL, pkey)) {
            OPENSSL_print_err();
            EVP_PKEY_CTX_free(pctx);
            EVP_MD_CTX_free(mctx);

            return NULL;
        }
    }

    ECDSA_CTX* ctx = OPENSSL_malloc(sizeof(ECDSA_CTX));
    if (ctx == NULL) {
        OPENSSL_print_err();
        EVP_PKEY_CTX_free(pctx);
        EVP_MD_CTX_free(mctx);
        return NULL;
    }

    ctx->pkey = pkey;
    ctx->pctx = pctx;
    ctx->mctx = mctx;

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

    EVP_PKEY* pkey = ec_pkey_new(ec_key);
    if (pkey == NULL) {
        EC_KEY_free(ec_key);

        return OPENSSL_FAILURE;
    }

    ECDSA_CTX* ctx = ecdsa_create_ctx(mdNID, pkey, isSign);
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
        if (ctx->pctx != NULL) {
            EVP_PKEY_CTX_free(ctx->pctx);
            ctx->pctx = NULL;
        }
        if (ctx->pkey != NULL) {
            EVP_PKEY_free(ctx->pkey);
            ctx->pkey = NULL;
        }

        OPENSSL_free(ctx);
    }
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_ecdsaFreeCtx
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    ECDSA_CTX_free((ECDSA_CTX*)pointer);
}

uint8_t* ecdsa_sign(EVP_MD_CTX* ctx, const uint8_t* msg, size_t msg_len, size_t* sig_len) {
    if (ctx == NULL || msg == NULL || sig_len == NULL) {
        return NULL;
    }

    if (!EVP_DigestSignUpdate(ctx, msg, msg_len)) {
        OPENSSL_print_err();

        return NULL;
    }

    if (!EVP_DigestSignFinal(ctx, NULL, sig_len)) {
        OPENSSL_print_err();

        return NULL;
    }

    uint8_t* sig_buf = (uint8_t*)OPENSSL_malloc(*sig_len);
    if (sig_buf == NULL) {
        OPENSSL_print_err();

        return NULL;
    }

    if (!EVP_DigestSignFinal(ctx, sig_buf, sig_len)) {
        OPENSSL_print_err();
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
    uint8_t* sig_buf = ecdsa_sign(ctx->mctx, (uint8_t*)msg_bytes, msg_len, &sig_len);
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

    if (!EVP_DigestSignInit(ctx->mctx, NULL, NULL, NULL, NULL)) {
        OPENSSL_print_err();

        return NULL;
    }

    return sig_bytes;
}

int ecdsa_verify(EVP_MD_CTX* ctx, const uint8_t* msg, size_t msg_len, const uint8_t* sig, size_t sig_len) {
    if (ctx == NULL) {
        return OPENSSL_FAILURE;
    }

    if (!EVP_DigestVerifyUpdate(ctx, msg, msg_len)) {
        OPENSSL_print_err();

        return OPENSSL_FAILURE;
    }

    if (!EVP_DigestVerifyFinal(ctx, sig, sig_len)) {
        OPENSSL_print_err();

        return OPENSSL_FAILURE;
    }

    return OPENSSL_SUCCESS;
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

    int verified = ecdsa_verify(ctx->mctx, (uint8_t*)msg_bytes, msg_len, (uint8_t*)sig_bytes, sig_len)
                   ? OPENSSL_SUCCESS : OPENSSL_FAILURE;

    (*env)->ReleaseByteArrayElements(env, message, msg_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, sig_bytes, JNI_ABORT);

    if (!EVP_DigestVerifyInit(ctx->mctx, NULL, NULL, NULL, NULL)) {
        OPENSSL_print_err();

        return OPENSSL_FAILURE;
    }

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

    EC_KEY* ec_key = ec_pri_key_new(curveNID, (const uint8_t *) key_bytes,
                                    key_len);
    (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
    if (ec_key == NULL) {
        return NULL;
    }

    EVP_PKEY* pkey = ec_pkey_new(ec_key);
    if (pkey == NULL) {
        EC_KEY_free(ec_key);

        return NULL;
    }

    ECDSA_CTX* ctx = ecdsa_create_ctx(mdNID, pkey, true);
    if (ctx == NULL) {
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);

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
    uint8_t* sig_buf = ecdsa_sign(ctx->mctx, (uint8_t*)msg_bytes, msg_len, &sig_len);
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

    EC_KEY* ec_key = ec_pub_key_new(curveNID, (const uint8_t *) key_bytes,
                                    key_len);
    (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
    if (ec_key == NULL) {
        return OPENSSL_FAILURE;
    }

    EVP_PKEY* pkey = ec_pkey_new(ec_key);
    if (pkey == NULL) {
        EC_KEY_free(ec_key);

        return OPENSSL_FAILURE;
    }

    ECDSA_CTX* ctx = ecdsa_create_ctx(mdNID, pkey, false);
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);
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

    int verified = ecdsa_verify(ctx->mctx, (uint8_t*)msg_bytes, msg_len, (uint8_t*)sig_bytes, sig_len)
                   ? OPENSSL_SUCCESS : OPENSSL_FAILURE;

    (*env)->ReleaseByteArrayElements(env, message, msg_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, sig_bytes, JNI_ABORT);

    ECDSA_CTX_free(ctx);

    return verified;
}
