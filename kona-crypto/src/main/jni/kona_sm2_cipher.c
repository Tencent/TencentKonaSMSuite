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
} SM2_CIPHER_CTX;

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2CipherCreateCtx
  (JNIEnv* env, jobject thisObj, jbyteArray key) {
    int key_len = (*env)->GetArrayLength(env, key);
    if (key_len < SM2_PRI_KEY_LEN) {
        return OPENSSL_FAILURE;
    }
    jbyte* key_bytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (key_bytes == NULL) {
        return OPENSSL_FAILURE;
    }

    EVP_PKEY* pkey = NULL;
    if (key_len == SM2_PRI_KEY_LEN) {
        uint8_t* pub_key_buf = OPENSSL_malloc(SM2_PUB_KEY_LEN);
        if (!pub_key_buf) {
            (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);

            return OPENSSL_FAILURE;
        }

        if (!sm2_gen_pub_key((const uint8_t*)key_bytes, pub_key_buf)) {
            OPENSSL_free(pub_key_buf);
            (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);

            return OPENSSL_FAILURE;
        }

        pkey = load_key_pair((const uint8_t*)key_bytes, pub_key_buf);

        OPENSSL_free(pub_key_buf);
    } else if (key_len == SM2_PUB_KEY_LEN) {
        pkey = load_pub_key((const uint8_t*)key_bytes, key_len);
    } else if (key_len == (SM2_PRI_KEY_LEN + SM2_PUB_KEY_LEN)) {
        uint8_t* pri_key_buf = OPENSSL_malloc(SM2_PRI_KEY_LEN);
        if (!pri_key_buf) {
            (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
            return OPENSSL_FAILURE;
        }
        memcpy(pri_key_buf, (const uint8_t*)key_bytes, SM2_PRI_KEY_LEN);

        uint8_t* pub_key_buf = OPENSSL_malloc(SM2_PUB_KEY_LEN);
        if (!pub_key_buf) {
            OPENSSL_free(pri_key_buf);
            (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
            return OPENSSL_FAILURE;
        }
        memcpy(pub_key_buf, (const uint8_t*)key_bytes + SM2_PRI_KEY_LEN, SM2_PUB_KEY_LEN);

        pkey = load_key_pair((const uint8_t*)pri_key_buf, pub_key_buf);
        OPENSSL_free(pri_key_buf);
        OPENSSL_free(pub_key_buf);
    }

    (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);

    if (pkey == NULL) {
        return OPENSSL_FAILURE;
    }

    EVP_PKEY_CTX* pctx = sm2_create_pkey_ctx(pkey);
    if (pctx == NULL) {
        EVP_PKEY_free(pkey);
        return OPENSSL_FAILURE;
    }

    SM2_CIPHER_CTX* ctx = (SM2_CIPHER_CTX*)OPENSSL_malloc(sizeof(SM2_CIPHER_CTX));
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return OPENSSL_FAILURE;
    }
    ctx->pkey = pkey;
    ctx->pctx = pctx;

    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2CipherFreeCtx
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    SM2_CIPHER_CTX* ctx = (SM2_CIPHER_CTX*)pointer;
    if (ctx != NULL) {
        if (ctx->pkey != NULL) {
            EVP_PKEY_free(ctx->pkey);
        }
        if (ctx->pctx != NULL) {
            EVP_PKEY_CTX_free(ctx->pctx);
        }
        OPENSSL_free(ctx);
    }
}

uint8_t* sm2_encrypt(EVP_PKEY_CTX* ctx, const uint8_t* plaintext, size_t plaintext_len, size_t* ciphertext_len) {
    if (ctx == NULL) {
        return NULL;
    }

    if (!EVP_PKEY_encrypt_init(ctx)) {
        OPENSSL_print_err();

        return NULL;
    }

    if (!EVP_PKEY_encrypt(ctx, NULL, ciphertext_len, plaintext, plaintext_len)) {
        OPENSSL_print_err();

        return NULL;
    }

    uint8_t* ciphertext = (uint8_t*)OPENSSL_malloc(*ciphertext_len);
    if (ciphertext == NULL) {
        OPENSSL_print_err();

        return NULL;
    }

    if (!EVP_PKEY_encrypt(ctx, ciphertext, ciphertext_len, plaintext, plaintext_len)) {
        OPENSSL_print_err();
        OPENSSL_free(ciphertext);

        return NULL;
    }

    return ciphertext;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2CipherEncrypt
  (JNIEnv* env, jobject thisObj, jlong pointer, jbyteArray plaintext) {
    SM2_CIPHER_CTX* ctx = (SM2_CIPHER_CTX*)pointer;
    if (ctx == NULL) {
        return NULL;
    }

    jsize plaintext_len = (*env)->GetArrayLength(env, plaintext);
    if (plaintext_len == 0) {
        return NULL;
    }
    jbyte* plaintext_bytes = (*env)->GetByteArrayElements(env, plaintext, NULL);
    if (plaintext_bytes == NULL) {
        return NULL;
    }

    size_t ciphertext_len;
    uint8_t* ciphertext_buf = sm2_encrypt(ctx->pctx, (const uint8_t*)plaintext_bytes, plaintext_len, &ciphertext_len);
    if (ciphertext_buf == NULL) {
        (*env)->ReleaseByteArrayElements(env, plaintext, plaintext_bytes, JNI_ABORT);

        return NULL;
    }

    jbyteArray ciphertext_bytes = (*env)->NewByteArray(env, ciphertext_len);
    if (ciphertext_bytes == NULL) {
        OPENSSL_free(ciphertext_buf);
        (*env)->ReleaseByteArrayElements(env, plaintext, plaintext_bytes, JNI_ABORT);

        return NULL;
    }
    (*env)->SetByteArrayRegion(env, ciphertext_bytes, 0, ciphertext_len, (jbyte*)ciphertext_buf);

    OPENSSL_free(ciphertext_buf);
    (*env)->ReleaseByteArrayElements(env, plaintext, plaintext_bytes, JNI_ABORT);

    return ciphertext_bytes;
}

uint8_t* sm2_decrypt(EVP_PKEY_CTX* ctx, const uint8_t* ciphertext, size_t ciphertext_len, size_t* cleartext_len) {
    if (ctx == NULL) {
        OPENSSL_print_err();

        return NULL;
    }

    if (!EVP_PKEY_decrypt_init(ctx)) {
        OPENSSL_print_err();

        return NULL;
    }

    if (!EVP_PKEY_decrypt(ctx, NULL, cleartext_len, ciphertext, ciphertext_len)) {
        OPENSSL_print_err();

        return NULL;
    }

    uint8_t* cleartext = (uint8_t*)OPENSSL_malloc(*cleartext_len);
    if (cleartext == NULL) {
        OPENSSL_print_err();

        return NULL;
    }

    if (!EVP_PKEY_decrypt(ctx, cleartext, cleartext_len, ciphertext, ciphertext_len)) {
        OPENSSL_print_err();
        OPENSSL_free(cleartext);
        return NULL;
    }

    return cleartext;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2CipherDecrypt
  (JNIEnv* env, jobject thisObj, jlong pointer, jbyteArray ciphertext) {
    SM2_CIPHER_CTX* ctx = (SM2_CIPHER_CTX*)pointer;
    if (ctx == NULL) {
        return NULL;
    }

    jsize ciphertext_len = (*env)->GetArrayLength(env, ciphertext);
    if (ciphertext_len == 0) {
        return NULL;
    }
    jbyte* ciphertext_bytes = (*env)->GetByteArrayElements(env, ciphertext, NULL);
    if (ciphertext_bytes == NULL) {
        return NULL;
    }

    size_t cleartext_len = 0;
    uint8_t* cleartext_buf = sm2_decrypt(ctx->pctx, (const uint8_t*)ciphertext_bytes, ciphertext_len, &cleartext_len);
    if (cleartext_buf == NULL) {
        (*env)->ReleaseByteArrayElements(env, ciphertext, ciphertext_bytes, JNI_ABORT);

        return NULL;
    }

    jbyteArray cleartext_bytes = (*env)->NewByteArray(env, cleartext_len);
    if (cleartext_bytes == NULL) {
        OPENSSL_free(cleartext_buf);
        (*env)->ReleaseByteArrayElements(env, ciphertext, ciphertext_bytes, JNI_ABORT);

        return NULL;
    }
    (*env)->SetByteArrayRegion(env, cleartext_bytes, 0, cleartext_len, (jbyte*)cleartext_buf);

    OPENSSL_free(cleartext_buf);
    (*env)->ReleaseByteArrayElements(env, ciphertext, ciphertext_bytes, JNI_ABORT);

    return cleartext_bytes;
}
