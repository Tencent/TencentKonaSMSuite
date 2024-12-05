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

typedef struct {
    EVP_PKEY* pkey;
    EVP_PKEY_CTX* pctx;
    EVP_MD_CTX* mctx;
} SM2_SIGNATURE_CTX;

SM2_SIGNATURE_CTX* sm2_create_md_ctx(EVP_PKEY* pkey, const uint8_t* id, size_t id_len, bool is_sign) {
    if (pkey == NULL || id == NULL || id_len == 0) {
        return NULL;
    }

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pctx == NULL) {
        OPENSSL_print_err();
        return NULL;
    }

    if (!EVP_PKEY_CTX_set1_id(pctx, id, id_len)) {
        OPENSSL_print_err();
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        OPENSSL_print_err();
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);

    if (is_sign) {
        if (!EVP_DigestSignInit(mctx, NULL, EVP_sm3(), NULL, pkey)) {
            OPENSSL_print_err();
            EVP_PKEY_CTX_free(pctx);
            EVP_MD_CTX_free(mctx);
            return NULL;
        }
    } else {
        if (!EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL, pkey)) {
            OPENSSL_print_err();
            EVP_PKEY_CTX_free(pctx);
            EVP_MD_CTX_free(mctx);
            return NULL;
        }
    }

    SM2_SIGNATURE_CTX* ctx = OPENSSL_malloc(sizeof(SM2_SIGNATURE_CTX));
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

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2SignatureCreateCtx
  (JNIEnv* env, jobject thisObj, jbyteArray key, jbyteArray id, jboolean isSign) {
    int key_len = (*env)->GetArrayLength(env, key);
    if (key_len < SM2_PRI_KEY_LEN) {
        return KONA_BAD;
    }
    jbyte* key_bytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (key_bytes == NULL) {
        return KONA_BAD;
    }

    int id_len = (*env)->GetArrayLength(env, id);
    if (id_len <= 0) {
        (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
        return KONA_BAD;
    }
    jbyte* id_bytes = (*env)->GetByteArrayElements(env, id, NULL);
    if (id_bytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
        return KONA_BAD;
    }

    EVP_PKEY* pkey = NULL;
    if (key_len == SM2_PRI_KEY_LEN) {
        uint8_t* pub_key_buf = OPENSSL_malloc(SM2_PUB_KEY_LEN);
        if (!pub_key_buf) {
            (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
            (*env)->ReleaseByteArrayElements(env, id, id_bytes, JNI_ABORT);

            return KONA_BAD;
        }

        if (!sm2_gen_pub_key((const uint8_t*)key_bytes, pub_key_buf)) {
            OPENSSL_free(pub_key_buf);
            (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
            (*env)->ReleaseByteArrayElements(env, id, id_bytes, JNI_ABORT);

            return KONA_BAD;
        }

        pkey = load_key_pair((const uint8_t*)key_bytes, pub_key_buf);

        OPENSSL_free(pub_key_buf);
    } else if (key_len == SM2_PUB_KEY_LEN) {
        pkey = load_pub_key((const uint8_t*)key_bytes, key_len);
    } else if (key_len == (SM2_PRI_KEY_LEN + SM2_PUB_KEY_LEN)) {
        uint8_t* pri_key_buf = OPENSSL_malloc(SM2_PRI_KEY_LEN);
        uint8_t* pub_key_buf = OPENSSL_malloc(SM2_PUB_KEY_LEN);
        if (!pri_key_buf || !pub_key_buf) {
            OPENSSL_free(pri_key_buf);
            OPENSSL_free(pub_key_buf);
            (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
            (*env)->ReleaseByteArrayElements(env, id, id_bytes, JNI_ABORT);
            return KONA_BAD;
        }

        memcpy(pri_key_buf, (const uint8_t*)key_bytes, SM2_PRI_KEY_LEN);
        memcpy(pub_key_buf, (const uint8_t*)key_bytes + SM2_PRI_KEY_LEN, SM2_PUB_KEY_LEN);

        pkey = load_key_pair((const uint8_t*)pri_key_buf, pub_key_buf);

        OPENSSL_free(pri_key_buf);
        OPENSSL_free(pub_key_buf);
    }

    if (pkey == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, id, id_bytes, JNI_ABORT);
        return KONA_BAD;
    }

    SM2_SIGNATURE_CTX* ctx = sm2_create_md_ctx(pkey, (const uint8_t*)id_bytes, id_len, isSign);

    (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, id, id_bytes, JNI_ABORT);

    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2SignatureFreeCtx
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    SM2_SIGNATURE_CTX* ctx = (SM2_SIGNATURE_CTX*)pointer;
    if (ctx != NULL) {
        EVP_MD_CTX_free(ctx->mctx);
        EVP_PKEY_CTX_free(ctx->pctx);
        EVP_PKEY_free(ctx->pkey);
        OPENSSL_free(ctx);
    }
}

uint8_t* sm2_sign(EVP_MD_CTX* ctx, const uint8_t* msg, size_t msg_len, size_t* sig_len) {
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

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2SignatureSign
  (JNIEnv* env, jobject thisObj, jlong pointer, jbyteArray message) {
    SM2_SIGNATURE_CTX* ctx = (SM2_SIGNATURE_CTX*)pointer;
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
    uint8_t* sig_buf = sm2_sign(ctx->mctx, (uint8_t*)msg_bytes, msg_len, &sig_len);

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

int sm2_verify(EVP_MD_CTX* ctx, const uint8_t* msg, size_t msg_len, const uint8_t* sig, size_t sig_len) {
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

JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2SignatureVerify
  (JNIEnv* env, jobject thisObj, jlong pointer, jbyteArray message, jbyteArray signature) {
    SM2_SIGNATURE_CTX* ctx = (SM2_SIGNATURE_CTX*)pointer;
    if (ctx == NULL) {
        return KONA_BAD;
    }

    jsize msg_len = (*env)->GetArrayLength(env, message);
    jbyte* msg_bytes = (*env)->GetByteArrayElements(env, message, NULL);
    if (msg_bytes == NULL) {
        return KONA_BAD;
    }

    jsize sig_len = (*env)->GetArrayLength(env, signature);
    jbyte* sig_bytes = (*env)->GetByteArrayElements(env, signature, NULL);
    if (sig_bytes == NULL) {
        (*env)->ReleaseByteArrayElements(env, message, msg_bytes, JNI_ABORT);
        return KONA_BAD;
    }

    int verified = sm2_verify(ctx->mctx, (uint8_t*)msg_bytes, msg_len, (uint8_t*)sig_bytes, sig_len)
            ? KONA_GOOD : KONA_BAD;

    (*env)->ReleaseByteArrayElements(env, message, msg_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, sig_bytes, JNI_ABORT);

    return verified;
}
