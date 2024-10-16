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

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "kona_crypto.h"

#define SM2_PRI_KEY_LEN      32
#define SM2_PUB_KEY_LEN      65
#define SM2_COMP_PUB_KEY_LEN 33
#define SM3_DIGEST_LEN       32
#define SM3_MAC_LEN          32
#define SM4_KEY_LEN          16
#define SM4_GCM_TAG_LEN      16

#define OPENSSL_SUCCESS       1
#define OPENSSL_FAILURE       0
#define KONA_GOOD             0
#define KONA_BAD             -1

#define KONA_print_err(...) fprintf(stderr, __VA_ARGS__)
#define OSSL_print_err() ERR_print_errors_fp(stderr)

void print_hex(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/* ***** SM3 start ***** */
int sm3_reset(EVP_MD_CTX *ctx) {
    if(!EVP_MD_CTX_reset(ctx)) {
        OSSL_print_err();
        return KONA_BAD;
    }

    const EVP_MD *md = EVP_sm3();
    if (!EVP_DigestInit_ex(ctx, md, NULL)) {
        OSSL_print_err();
        return KONA_BAD;
    }

    return KONA_GOOD;
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm3CreateCtx
  (JNIEnv *env, jobject thisObj) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        OSSL_print_err();
        return KONA_BAD;
    }

    const EVP_MD *md = EVP_sm3();
    if (!EVP_DigestInit_ex(ctx, md, NULL)) {
        OSSL_print_err();
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
        OSSL_print_err();
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
        OSSL_print_err();
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
        OSSL_print_err();
        return KONA_BAD;
    }

    if (!EVP_MD_CTX_copy_ex(new_ctx, orig_ctx)) {
        OSSL_print_err();
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
        OSSL_print_err();
        return KONA_BAD;
    }

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        OSSL_print_err();
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
        OSSL_print_err();
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
        OSSL_print_err();
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
        OSSL_print_err();
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
        OSSL_print_err();
        return KONA_BAD;
    }

    return (jlong)new_ctx;
}
/* ***** SM3HMAC end ***** */


/* ***** SM4 start ***** */
JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4CreateCtx
  (JNIEnv *env, jobject thisObj, jboolean encrypt, jstring mode, jboolean padding, jbyteArray key, jbyteArray iv) {
    if (key == NULL) {
        return KONA_BAD;
    }

    const char *mode_str = (*env)->GetStringUTFChars(env, mode, 0);
    const char *sm4_mode;
    if (strcmp(mode_str, "ECB") == 0) {
        sm4_mode = "SM4-ECB";
    } else if (strcmp(mode_str, "CBC") == 0) {
        sm4_mode = "SM4-CBC";
    } else if (strcmp(mode_str, "CTR") == 0) {
        sm4_mode = "SM4-CTR";
    } else if (strcmp(mode_str, "GCM") == 0) {
        sm4_mode = "SM4-GCM";
    } else {
        return KONA_BAD;
    }

    const EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, sm4_mode, NULL);
    if (cipher == NULL) {
        OSSL_print_err();
        return KONA_BAD;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        OSSL_print_err();
        return KONA_BAD;
    }

    jbyte *key_bytes = (*env)->GetByteArrayElements(env, key, NULL);
    jbyte *iv_bytes = iv ? (*env)->GetByteArrayElements(env, iv, NULL) : NULL;

    long result;
    if (EVP_CipherInit_ex(ctx, cipher, NULL, (unsigned char *)key_bytes, (unsigned char *)iv_bytes, encrypt)) {
        result = (long)ctx;
    } else {
        OSSL_print_err();
        result = KONA_BAD;
    }

    if (!padding && !EVP_CIPHER_CTX_set_padding(ctx, 0)) {
        OSSL_print_err();
        result = KONA_BAD;
    }

    // Clean
    (*env)->ReleaseStringUTFChars(env, mode, mode_str);
    (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
    if (iv_bytes) (*env)->ReleaseByteArrayElements(env, iv, iv_bytes, JNI_ABORT);

    return (jlong)result;
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4FreeCtx
  (JNIEnv *env, jobject thisObj, jlong pointer) {
    if (pointer <= 0) {
        return;
    }

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)pointer;
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4Update
  (JNIEnv *env, jobject thisObj, jlong pointer, jbyteArray in) {
    if (pointer <= 0) {
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)pointer;
    if (ctx == NULL) {
        return NULL;
    }

    jbyte *in_bytes = (*env)->GetByteArrayElements(env, in, NULL);
    if (in_bytes == NULL) {
        return NULL;
    }
    jsize in_len = (*env)->GetArrayLength(env, in);

    int out_len = in_len + EVP_CIPHER_CTX_block_size(ctx);
    unsigned char *out_buf = (unsigned char *)malloc(out_len);
    if (out_buf == NULL) {
        (*env)->ReleaseByteArrayElements(env, in, in_bytes, JNI_ABORT);
        return NULL;
    }

    jbyteArray out_bytes;
    int len;
    if (EVP_CipherUpdate(ctx, out_buf, &len, (unsigned char *)in_bytes, in_len)) {
        out_bytes = (*env)->NewByteArray(env, len);
        if (len > 0) {
            (*env)->SetByteArrayRegion(env, out_bytes, 0, len, (jbyte *)out_buf);
        }
    } else {
        OSSL_print_err();
        out_bytes = NULL;
    }

    (*env)->ReleaseByteArrayElements(env, in, in_bytes, JNI_ABORT);
    free(out_buf);

    return out_bytes;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4Final
  (JNIEnv *env, jobject thisObj, jlong pointer) {
    if (pointer <= 0) {
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)pointer;
    if (ctx == NULL) {
        return NULL;
    }

    int block_size = EVP_CIPHER_CTX_block_size(ctx);
    unsigned char *out_buf = (unsigned char *)malloc(block_size);
    if (out_buf == NULL) {
        return NULL;
    }

    jbyteArray out_bytes;
    int len;
    if (EVP_CipherFinal_ex(ctx, out_buf, &len)) {
        out_bytes = (*env)->NewByteArray(env, len);
        if (len > 0) {
            (*env)->SetByteArrayRegion(env, out_bytes, 0, len, (jbyte *)out_buf);
        }
    } else {
        OSSL_print_err();
        out_bytes = NULL;
    }

    free(out_buf);

    return out_bytes;
}

JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4GCMUpdateAAD
  (JNIEnv *env, jobject thisObj, jlong pointer, jbyteArray aad) {
    if (pointer <= 0) {
        return KONA_BAD;
    }

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)pointer;
    if (ctx == NULL) {
        return KONA_BAD;
    }

    if (aad == NULL) {
        return KONA_BAD;
    }

    int aad_len = (*env)->GetArrayLength(env, aad);
    jbyte *aad_bytes = (*env)->GetByteArrayElements(env, aad, NULL);
    int out_len = 0;
    int result;
    if (EVP_CipherUpdate(ctx, NULL, &out_len, (unsigned char *)aad_bytes, aad_len)) {
        result = KONA_GOOD;
    } else {
        OSSL_print_err();
        result = KONA_BAD;
    }

    (*env)->ReleaseByteArrayElements(env, aad, aad_bytes, JNI_ABORT);

    return result;
}

JNIEXPORT jint JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm4GCMProcTag
  (JNIEnv *env, jobject thisObj, jlong pointer, jbyteArray tag) {
    if (pointer <= 0) {
        return KONA_BAD;
    }

    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)pointer;
    if (ctx == NULL) {
        return KONA_BAD;
    }

    if (tag == NULL) {
        return KONA_BAD;
    }

    int tag_len = (*env)->GetArrayLength(env, tag);
    if (tag_len != SM4_GCM_TAG_LEN) {
        return KONA_BAD;
    }

    int result;
    if (EVP_CIPHER_CTX_encrypting(ctx)) {
        unsigned char tag_buf[SM4_GCM_TAG_LEN];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SM4_GCM_TAG_LEN, tag_buf)) {
            (*env)->SetByteArrayRegion(env, tag, 0, SM4_GCM_TAG_LEN, (jbyte *)tag_buf);
            result = KONA_GOOD;
        } else {
            OSSL_print_err();
            result = KONA_BAD;
        }
    } else {
        jbyte *tag_bytes = (*env)->GetByteArrayElements(env, tag, NULL);
        if (tag_bytes == NULL) {
            result = KONA_BAD;
        } else {
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SM4_GCM_TAG_LEN, tag_bytes)) {
                result = KONA_GOOD;
            } else {
                OSSL_print_err();
                result = KONA_BAD;
            }

            (*env)->ReleaseByteArrayElements(env, tag, tag_bytes, JNI_ABORT);
        }
    }

    return result;
}
/* ***** SM4 end ***** */

/* ***** SM2 start ***** */
JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_toUncompPubKey
  (JNIEnv *env, jclass thisObj, jbyteArray compPubKey) {
    jbyte *comp_pub_key_bytes = (*env)->GetByteArrayElements(env, compPubKey, NULL);
    if (comp_pub_key_bytes == NULL) {
        return NULL;
    }
    jsize comp_pub_key_len = (*env)->GetArrayLength(env, compPubKey);
    if (comp_pub_key_len != SM2_COMP_PUB_KEY_LEN) {
        (*env)->ReleaseByteArrayElements(env, compPubKey, comp_pub_key_bytes, JNI_ABORT);
        return NULL;
    }

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (group == NULL) {
        OSSL_print_err();
        (*env)->ReleaseByteArrayElements(env, compPubKey, comp_pub_key_bytes, JNI_ABORT);
        return NULL;
    }

    EC_POINT *point = EC_POINT_new(group);
    if (point == NULL) {
        OSSL_print_err();
        (*env)->ReleaseByteArrayElements(env, compPubKey, comp_pub_key_bytes, JNI_ABORT);
        EC_GROUP_free(group);
        return NULL;
    }

    // Convert the compressed public key to an EC_POINT
    if (!EC_POINT_oct2point(group, point, (unsigned char *)comp_pub_key_bytes, comp_pub_key_len, NULL)) {
        OSSL_print_err();
        (*env)->ReleaseByteArrayElements(env, compPubKey, comp_pub_key_bytes, JNI_ABORT);
        EC_GROUP_free(group);
        EC_POINT_free(point);
        return NULL;
    }

    // Convert the EC_POINT to an uncompressed public key
    unsigned char uncomp_pub_key[SM2_PUB_KEY_LEN];
    size_t uncomp_pub_key_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, uncomp_pub_key, SM2_PUB_KEY_LEN, NULL);
    if (uncomp_pub_key_len <= 0) {
        OSSL_print_err();
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
    (*env)->SetByteArrayRegion(env, uncompPubKey, 0, uncomp_pub_key_len, (jbyte *)uncomp_pub_key);

    return uncompPubKey;
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2CreateCtx
  (JNIEnv *env, jobject thisObj) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    if (ctx == NULL) {
        OSSL_print_err();
        return KONA_BAD;
    }

    if(!EVP_PKEY_keygen_init(ctx)) {
        OSSL_print_err();
        return KONA_BAD;
    }

    return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2FreeCtx
  (JNIEnv *env, jobject thisObj, jlong pointer) {
    if (pointer <= 0) {
        return;
    }

    EVP_PKEY_CTX *ctx = (EVP_PKEY_CTX *)pointer;
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2GenKeyPair
  (JNIEnv *env, jobject thisObj, jlong pointer) {
    EVP_PKEY_CTX *ctx = (EVP_PKEY_CTX *)pointer;
    if (ctx == NULL) {
        OSSL_print_err();
        return NULL;
    }

    if (!EVP_PKEY_keygen_init(ctx)) {
        OSSL_print_err();
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (!EVP_PKEY_keygen(ctx, &pkey)) {
        OSSL_print_err();
        return NULL;
    }

    BIGNUM *priv_key_bn = NULL;
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_key_bn)) {
        OSSL_print_err();
        EVP_PKEY_free(pkey);
        return NULL;
    }
    if (BN_num_bytes(priv_key_bn) > SM2_PRI_KEY_LEN) {
        EVP_PKEY_free(pkey);
        BN_free(priv_key_bn);
        return NULL;
    }
    unsigned char priv_key_buf[SM2_PRI_KEY_LEN] = {0};
    BN_bn2binpad(priv_key_bn, priv_key_buf, SM2_PRI_KEY_LEN);
    BN_free(priv_key_bn);

    size_t pub_key_len = 0;
    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_key_len)) {
        OSSL_print_err();
        EVP_PKEY_free(pkey);
        OPENSSL_cleanse(priv_key_buf, SM2_PRI_KEY_LEN);
        return NULL;
    }
    unsigned char *pub_key_buf = OPENSSL_malloc(pub_key_len);
    if (!pub_key_buf) {
        EVP_PKEY_free(pkey);
        OPENSSL_cleanse(priv_key_buf, SM2_PRI_KEY_LEN);
        return NULL;
    }
    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub_key_buf, pub_key_len, &pub_key_len)) {
        OSSL_print_err();
        EVP_PKEY_free(pkey);
        OPENSSL_cleanse(priv_key_buf, SM2_PRI_KEY_LEN);
        OPENSSL_free(pub_key_buf);
        return NULL;
    }

    size_t total_len = SM2_PRI_KEY_LEN + pub_key_len;
    jbyteArray result = (*env)->NewByteArray(env, total_len);
    if (result) {
        jbyte *result_bytes = (*env)->GetByteArrayElements(env, result, NULL);

        if (result_bytes) {
            memcpy(result_bytes, priv_key_buf, SM2_PRI_KEY_LEN);
            memcpy(result_bytes + SM2_PRI_KEY_LEN, pub_key_buf, pub_key_len);

            (*env)->ReleaseByteArrayElements(env, result, result_bytes, 0);
        }
    }

    EVP_PKEY_free(pkey);
    OPENSSL_cleanse(priv_key_buf, SM2_PRI_KEY_LEN);
    OPENSSL_free(pub_key_buf);

    return result;
}
/* ***** SM2 end ***** */
