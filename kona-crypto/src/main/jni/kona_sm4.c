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

#include <jni.h>

#include <openssl/evp.h>

#include "kona/kona_jni.h"
#include "kona/kona_common.h"

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4CreateCtx
  (JNIEnv* env, jobject thisObj, jboolean encrypt, jstring mode, jboolean padding, jbyteArray key, jbyteArray iv) {
    if (key == NULL) {
        return KONA_BAD;
    }

    const char* mode_str = (*env)->GetStringUTFChars(env, mode, 0);
    const char* sm4_mode = NULL;

    if (strcmp(mode_str, "ECB") == 0) {
        sm4_mode = "SM4-ECB";
    } else if (strcmp(mode_str, "CBC") == 0) {
        sm4_mode = "SM4-CBC";
    } else if (strcmp(mode_str, "CTR") == 0) {
        sm4_mode = "SM4-CTR";
    } else if (strcmp(mode_str, "GCM") == 0) {
        sm4_mode = "SM4-GCM";
    } else {
        (*env)->ReleaseStringUTFChars(env, mode, mode_str);
        return KONA_BAD;
    }

    const EVP_CIPHER* cipher = EVP_CIPHER_fetch(NULL, sm4_mode, NULL);
    if (cipher == NULL) {
        OPENSSL_print_err();
        (*env)->ReleaseStringUTFChars(env, mode, mode_str);
        return KONA_BAD;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        OPENSSL_print_err();
        (*env)->ReleaseStringUTFChars(env, mode, mode_str);
        return KONA_BAD;
    }

    jbyte* key_bytes = (*env)->GetByteArrayElements(env, key, NULL);
    jbyte* iv_bytes = iv ? (*env)->GetByteArrayElements(env, iv, NULL) : NULL;

    jlong result = KONA_BAD;
    if (EVP_CipherInit_ex(ctx, cipher, NULL, (uint8_t*)key_bytes, (uint8_t*)iv_bytes, encrypt)) {
        if (!padding && !EVP_CIPHER_CTX_set_padding(ctx, 0)) {
            OPENSSL_print_err();
        } else {
            result = (jlong)ctx;
        }
    } else {
        OPENSSL_print_err();
    }

    (*env)->ReleaseStringUTFChars(env, mode, mode_str);
    (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
    if (iv_bytes) {
        (*env)->ReleaseByteArrayElements(env, iv, iv_bytes, JNI_ABORT);
    }

    if (result == KONA_BAD && ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }

    return result;
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4FreeCtx
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    EVP_CIPHER_CTX* ctx = (EVP_CIPHER_CTX*)pointer;
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4Update
  (JNIEnv* env, jobject thisObj, jlong pointer, jbyteArray in) {
    EVP_CIPHER_CTX* ctx = (EVP_CIPHER_CTX*)pointer;
    if (ctx == NULL) {
        return NULL;
    }

    jbyte* in_bytes = (*env)->GetByteArrayElements(env, in, NULL);
    if (in_bytes == NULL) {
        return NULL;
    }
    jsize in_len = (*env)->GetArrayLength(env, in);

    int out_len = in_len + EVP_CIPHER_CTX_block_size(ctx);
    uint8_t* out_buf = (uint8_t*)OPENSSL_malloc(out_len);
    if (out_buf == NULL) {
        (*env)->ReleaseByteArrayElements(env, in, in_bytes, JNI_ABORT);
        return NULL;
    }

    jbyteArray out_bytes = NULL;
    int len = 0;
    if (EVP_CipherUpdate(ctx, out_buf, &len, (uint8_t*)in_bytes, in_len)) {
        out_bytes = (*env)->NewByteArray(env, len);
        if (out_bytes != NULL && len > 0) {
            (*env)->SetByteArrayRegion(env, out_bytes, 0, len, (jbyte*)out_buf);
        }
    } else {
        OPENSSL_print_err();
    }

    (*env)->ReleaseByteArrayElements(env, in, in_bytes, JNI_ABORT);
    OPENSSL_free(out_buf);

    return out_bytes;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4Final
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    EVP_CIPHER_CTX* ctx = (EVP_CIPHER_CTX*)pointer;
    if (ctx == NULL) {
        return NULL;
    }

    int block_size = EVP_CIPHER_CTX_block_size(ctx);
    uint8_t* out_buf = (uint8_t*)OPENSSL_malloc(block_size);
    if (out_buf == NULL) {
        return NULL;
    }

    jbyteArray out_bytes = NULL;
    int len = 0;
    if (EVP_CipherFinal_ex(ctx, out_buf, &len)) {
        out_bytes = (*env)->NewByteArray(env, len);
        if (out_bytes != NULL && len > 0) {
            (*env)->SetByteArrayRegion(env, out_bytes, 0, len, (jbyte*)out_buf);
        }
    } else {
        OPENSSL_print_err();
    }

    OPENSSL_free(out_buf);

    return out_bytes;
}

JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4GCMUpdateAAD
  (JNIEnv* env, jobject thisObj, jlong pointer, jbyteArray aad) {
    EVP_CIPHER_CTX* ctx = (EVP_CIPHER_CTX*)pointer;
    if (ctx == NULL || aad == NULL) {
        return KONA_BAD;
    }

    int aad_len = (*env)->GetArrayLength(env, aad);
    if (aad_len <= 0) {
        return KONA_BAD;
    }

    jbyte* aad_bytes = (*env)->GetByteArrayElements(env, aad, NULL);
    if (aad_bytes == NULL) {
        return KONA_BAD;
    }

    int out_len = 0;
    int result = KONA_BAD;
    if (EVP_CipherUpdate(ctx, NULL, &out_len, (uint8_t*)aad_bytes, aad_len)) {
        result = KONA_GOOD;
    } else {
        OPENSSL_print_err();
    }

    (*env)->ReleaseByteArrayElements(env, aad, aad_bytes, JNI_ABORT);

    return result;
}

JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4GCMProcTag
  (JNIEnv* env, jobject thisObj, jlong pointer, jbyteArray tag) {
    EVP_CIPHER_CTX* ctx = (EVP_CIPHER_CTX*)pointer;
    if (ctx == NULL || tag == NULL) {
        return KONA_BAD;
    }

    int tag_len = (*env)->GetArrayLength(env, tag);
    if (tag_len != SM4_GCM_TAG_LEN) {
        return KONA_BAD;
    }

    int result = KONA_BAD;
    if (EVP_CIPHER_CTX_encrypting(ctx)) {
        uint8_t tag_buf[SM4_GCM_TAG_LEN];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SM4_GCM_TAG_LEN, tag_buf)) {
            (*env)->SetByteArrayRegion(env, tag, 0, SM4_GCM_TAG_LEN, (jbyte*)tag_buf);
            result = KONA_GOOD;
        } else {
            OPENSSL_print_err();
        }
    } else {
        jbyte* tag_bytes = (*env)->GetByteArrayElements(env, tag, NULL);
        if (tag_bytes != NULL) {
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SM4_GCM_TAG_LEN, tag_bytes)) {
                result = KONA_GOOD;
            } else {
                OPENSSL_print_err();
            }

            (*env)->ReleaseByteArrayElements(env, tag, tag_bytes, JNI_ABORT);
        }
    }

    return result;
}
