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

#include "kona_common.h"

/* ***** SM2 MISC start ***** */
JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2ToUncompPubKey
  (JNIEnv* env, jobject thisObj, jbyteArray compPubKey) {
    jsize comp_pub_key_len = (*env)->GetArrayLength(env, compPubKey);
    if (comp_pub_key_len != SM2_COMP_PUB_KEY_LEN) {
        return NULL;
    }
    jbyte* comp_pub_key_bytes = (*env)->GetByteArrayElements(env, compPubKey, NULL);
    if (comp_pub_key_bytes == NULL) {
        return NULL;
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (group == NULL) {
        OPENSSL_print_err();
        (*env)->ReleaseByteArrayElements(env, compPubKey, comp_pub_key_bytes, JNI_ABORT);
        return NULL;
    }

    EC_POINT* point = EC_POINT_new(group);
    if (point == NULL) {
        OPENSSL_print_err();
        (*env)->ReleaseByteArrayElements(env, compPubKey, comp_pub_key_bytes, JNI_ABORT);
        EC_GROUP_free(group);
        return NULL;
    }

    // Convert the compressed public key to an EC_POINT
    if (!EC_POINT_oct2point(group, point, (unsigned char*)comp_pub_key_bytes, comp_pub_key_len, NULL)) {
        OPENSSL_print_err();
        (*env)->ReleaseByteArrayElements(env, compPubKey, comp_pub_key_bytes, JNI_ABORT);
        EC_GROUP_free(group);
        EC_POINT_free(point);
        return NULL;
    }

    // Convert the EC_POINT to an uncompressed public key
    unsigned char uncomp_pub_key[SM2_PUB_KEY_LEN];
    size_t uncomp_pub_key_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, uncomp_pub_key, SM2_PUB_KEY_LEN, NULL);
    if (uncomp_pub_key_len <= 0) {
        OPENSSL_print_err();
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
    (*env)->SetByteArrayRegion(env, uncompPubKey, 0, uncomp_pub_key_len, (jbyte*)uncomp_pub_key);

    return uncompPubKey;
}
/* ***** SM2 MISC end ***** */

/* ***** SM2 key gen start ***** */
EVP_PKEY* load_pub_key(const unsigned char* pub_key, size_t pub_key_len) {
    EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    if (key_ctx == NULL) {
        OPENSSL_print_err();
        return NULL;
    }

    if (!EVP_PKEY_fromdata_init(key_ctx)) {
        OPENSSL_print_err();
        EVP_PKEY_CTX_free(key_ctx);
        return NULL;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "SM2", 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)pub_key, pub_key_len),
        OSSL_PARAM_construct_end()
    };

    EVP_PKEY* pkey = NULL;
    if (!EVP_PKEY_fromdata(key_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params)) {
        OPENSSL_print_err();
        EVP_PKEY_CTX_free(key_ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(key_ctx);
    return pkey;
}

EVP_PKEY* load_key_pair(const unsigned char* pri_key, const unsigned char* pub_key) {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (ec_key == NULL) {
        OPENSSL_print_err();
        return NULL;
    }

    BIGNUM* pri_key_bn = BN_bin2bn(pri_key, SM2_PRI_KEY_LEN, NULL);
    if (pri_key_bn == NULL) {
        OPENSSL_print_err();
        EC_KEY_free(ec_key);

        return NULL;
    }

    if (!EC_KEY_set_private_key(ec_key, pri_key_bn)) {
        OPENSSL_print_err();
        BN_free(pri_key_bn);
        EC_KEY_free(ec_key);

        return NULL;
    }

    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    EC_POINT* pub_point = EC_POINT_new(group);
    if (pub_point == NULL) {
        OPENSSL_print_err();
        BN_free(pri_key_bn);
        EC_KEY_free(ec_key);

        return NULL;
    }

    if (!EC_POINT_oct2point(group, pub_point, pub_key, SM2_PUB_KEY_LEN, NULL)) {
        OPENSSL_print_err();
        BN_free(pri_key_bn);
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);

        return NULL;
    }

    if (!EC_KEY_set_public_key(ec_key, pub_point)) {
        OPENSSL_print_err();
        BN_free(pri_key_bn);
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);

        return NULL;
    }

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        OPENSSL_print_err();

        BN_free(pri_key_bn);
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);

        return NULL;
    }

    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        OPENSSL_print_err();
        EVP_PKEY_free(pkey);

        BN_free(pri_key_bn);
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);

        return NULL;
    }

    BN_free(pri_key_bn);
    EC_POINT_free(pub_point);
    ec_key = NULL; // ec_key cannot be freed due pkey is using it.

    return pkey;
}

int sm2_gen_pub_key(const unsigned char* pri_key, unsigned char* pub_key) {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (ec_key == NULL) {
        return OPENSSL_FAILURE;
    }

    BIGNUM* bn_pri_key = BN_bin2bn(pri_key, SM2_PRI_KEY_LEN, NULL);
    if (bn_pri_key == NULL) {
        EC_KEY_free(ec_key);
        return OPENSSL_FAILURE;
    }

    if (!EC_KEY_set_private_key(ec_key, bn_pri_key)) {
        EC_KEY_free(ec_key);
        BN_free(bn_pri_key);
        return OPENSSL_FAILURE;
    }

    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    if (group == NULL) {
        EC_KEY_free(ec_key);
        BN_free(bn_pri_key);
        return OPENSSL_FAILURE;
    }

    EC_POINT* pub_point = EC_POINT_new(group);
    if (pub_point == NULL) {
        EC_KEY_free(ec_key);
        BN_free(bn_pri_key);
        return OPENSSL_FAILURE;
    }

    if (!EC_POINT_mul(group, pub_point, bn_pri_key, NULL, NULL, NULL)) {
        EC_KEY_free(ec_key);
        BN_free(bn_pri_key);
        EC_POINT_free(pub_point);
        return OPENSSL_FAILURE;
    }

    if (!EC_KEY_set_public_key(ec_key, pub_point)) {
        EC_KEY_free(ec_key);
        BN_free(bn_pri_key);
        EC_POINT_free(pub_point);
        return OPENSSL_FAILURE;
    }

    BN_CTX* bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        EC_KEY_free(ec_key);
        BN_free(bn_pri_key);
        EC_POINT_free(pub_point);
        return OPENSSL_FAILURE;
    }

    size_t pub_key_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bn_ctx);
    if (pub_key_len != SM2_PUB_KEY_LEN) {
        EC_KEY_free(ec_key);
        BN_free(bn_pri_key);
        EC_POINT_free(pub_point);
        BN_CTX_free(bn_ctx);
        return OPENSSL_FAILURE;
    }

    if (!EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, pub_key, pub_key_len, bn_ctx)) {
        EC_KEY_free(ec_key);
        BN_free(bn_pri_key);
        EC_POINT_free(pub_point);
        BN_CTX_free(bn_ctx);
        return OPENSSL_FAILURE;
    }

    EC_KEY_free(ec_key);
    BN_free(bn_pri_key);
    EC_POINT_free(pub_point);
    BN_CTX_free(bn_ctx);

    return OPENSSL_SUCCESS;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2GenPubKey
  (JNIEnv* env, jobject thisObj, jbyteArray priKey) {
    jsize pri_key_len = (*env)->GetArrayLength(env, priKey);
    if (pri_key_len != SM2_PRI_KEY_LEN) {
        return NULL;
    }
    jbyte* pri_key_bytes = (*env)->GetByteArrayElements(env, priKey, NULL);
    if (pri_key_bytes == NULL) {
        return NULL;
    }

    unsigned char pub_key_buf[SM2_PUB_KEY_LEN];
    if (!sm2_gen_pub_key((const unsigned char*)pri_key_bytes, pub_key_buf)) {
        (*env)->ReleaseByteArrayElements(env, priKey, pri_key_bytes, JNI_ABORT);
        return NULL;
    }
    (*env)->ReleaseByteArrayElements(env, priKey, pri_key_bytes, JNI_ABORT);

    jbyteArray pubKey = (*env)->NewByteArray(env, SM2_PUB_KEY_LEN);
    if (pubKey == NULL) {
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, pubKey, 0, SM2_PUB_KEY_LEN, (jbyte*)pub_key_buf);

    return pubKey;
}

EVP_PKEY_CTX* sm2_create_ctx(EVP_PKEY* pkey) {
    EVP_PKEY_CTX* ctx = NULL;

    if (pkey != NULL) {
        ctx = EVP_PKEY_CTX_new(pkey, NULL);
    } else {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    }

    if (ctx == NULL) {
        OPENSSL_print_err();
        return NULL;
    }

    return ctx;
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2KeyPairGenCreateCtx
  (JNIEnv* env, jobject thisObj) {
    EVP_PKEY_CTX* ctx = sm2_create_ctx(NULL);
    return ctx == NULL ? KONA_BAD : (jlong)ctx;
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2KeyPairGenFreeCtx
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    EVP_PKEY_CTX* ctx = (EVP_PKEY_CTX*)pointer;
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
}

int sm2_gen_key_pair(EVP_PKEY_CTX* ctx, unsigned char* key_pair, size_t* key_pair_len) {
    if (ctx == NULL) {
        return OPENSSL_FAILURE;
    }

    if (!EVP_PKEY_keygen_init(ctx)) {
        OPENSSL_print_err();
        return OPENSSL_FAILURE;
    }

    EVP_PKEY* pkey = NULL;
    if (!EVP_PKEY_keygen(ctx, &pkey)) {
        OPENSSL_print_err();
        return OPENSSL_FAILURE;
    }

    BIGNUM* priv_key_bn = NULL;
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_key_bn)) {
        OPENSSL_print_err();
        EVP_PKEY_free(pkey);
        return OPENSSL_FAILURE;
    }
    if (BN_num_bytes(priv_key_bn) > SM2_PRI_KEY_LEN) {
        EVP_PKEY_free(pkey);
        BN_free(priv_key_bn);
        return OPENSSL_FAILURE;
    }
    unsigned char priv_key_buf[SM2_PRI_KEY_LEN] = {0};
    BN_bn2binpad(priv_key_bn, priv_key_buf, SM2_PRI_KEY_LEN);
    BN_free(priv_key_bn);

    size_t pub_key_len = 0;
    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_key_len)) {
        OPENSSL_print_err();
        EVP_PKEY_free(pkey);
        OPENSSL_cleanse(priv_key_buf, SM2_PRI_KEY_LEN);
        return OPENSSL_FAILURE;
    }
    unsigned char* pub_key_buf = OPENSSL_malloc(pub_key_len);
    if (pub_key_buf == NULL) {
        EVP_PKEY_free(pkey);
        OPENSSL_cleanse(priv_key_buf, SM2_PRI_KEY_LEN);
        return OPENSSL_FAILURE;
    }

    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub_key_buf, pub_key_len, &pub_key_len)) {
        OPENSSL_print_err();
        EVP_PKEY_free(pkey);
        OPENSSL_cleanse(priv_key_buf, SM2_PRI_KEY_LEN);
        OPENSSL_free(pub_key_buf);
        return OPENSSL_FAILURE;
    }

    *key_pair_len = SM2_PRI_KEY_LEN + pub_key_len;
    memcpy(key_pair, priv_key_buf, SM2_PRI_KEY_LEN);
    memcpy(key_pair + SM2_PRI_KEY_LEN, pub_key_buf, pub_key_len);

    EVP_PKEY_free(pkey);
    OPENSSL_cleanse(priv_key_buf, SM2_PRI_KEY_LEN);
    OPENSSL_free(pub_key_buf);

    return OPENSSL_SUCCESS;
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2KeyPairGenGenKeyPair
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    EVP_PKEY_CTX* ctx = (EVP_PKEY_CTX*)pointer;
    if (ctx == NULL) {
        return NULL;
    }

    size_t key_pair_len = SM2_PRI_KEY_LEN + SM2_PUB_KEY_LEN;
    unsigned char* key_pair_buf = OPENSSL_malloc(key_pair_len);
    if (key_pair_buf == NULL) {
        return NULL;
    }

    if (!sm2_gen_key_pair(ctx, key_pair_buf, &key_pair_len)) {
        OPENSSL_free(key_pair_buf);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, key_pair_len);
    if (result) {
        jbyte* result_bytes = (*env)->GetByteArrayElements(env, result, NULL);

        if (result_bytes) {
            memcpy(result_bytes, key_pair_buf, key_pair_len);
            (*env)->ReleaseByteArrayElements(env, result, result_bytes, 0);
        } else {
            (*env)->DeleteLocalRef(env, result);
            result = NULL;
        }
    }

    OPENSSL_free(key_pair_buf);

    return result;
}
/* ***** SM2 key gen end ***** */

/* ***** SM2 cipher start ***** */
typedef struct {
    EVP_PKEY* pkey;
    EVP_PKEY_CTX* pctx;
} SM2_CIPHER_CTX;

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2CipherCreateCtx
  (JNIEnv* env, jobject thisObj, jbyteArray key) {
    int key_len = (*env)->GetArrayLength(env, key);
    if (key_len < SM2_PRI_KEY_LEN) {
        return KONA_BAD;
    }
    jbyte* key_bytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (key_bytes == NULL) {
        return KONA_BAD;
    }

    EVP_PKEY* pkey = NULL;
    if (key_len == SM2_PRI_KEY_LEN) {
        unsigned char* pub_key_buf = OPENSSL_malloc(SM2_PUB_KEY_LEN);
        if (!pub_key_buf) {
            (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);

            return KONA_BAD;
        }

        if (!sm2_gen_pub_key((const unsigned char*)key_bytes, pub_key_buf)) {
            OPENSSL_free(pub_key_buf);
            (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);

            return KONA_BAD;
        }

        pkey = load_key_pair((const unsigned char*)key_bytes, pub_key_buf);

        OPENSSL_free(pub_key_buf);
    } else if (key_len == SM2_PUB_KEY_LEN) {
        pkey = load_pub_key((const unsigned char*)key_bytes, key_len);
    } else if (key_len == (SM2_PRI_KEY_LEN + SM2_PUB_KEY_LEN)) {
        unsigned char* pri_key_buf = OPENSSL_malloc(SM2_PRI_KEY_LEN);
        if (!pri_key_buf) {
            (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
            return KONA_BAD;
        }
        memcpy(pri_key_buf, (const unsigned char*)key_bytes, SM2_PRI_KEY_LEN);

        unsigned char* pub_key_buf = OPENSSL_malloc(SM2_PUB_KEY_LEN);
        if (!pub_key_buf) {
            OPENSSL_free(pri_key_buf);
            (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
            return KONA_BAD;
        }
        memcpy(pub_key_buf, (const unsigned char*)key_bytes + SM2_PRI_KEY_LEN, SM2_PUB_KEY_LEN);

        pkey = load_key_pair((const unsigned char*)pri_key_buf, pub_key_buf);
        OPENSSL_free(pri_key_buf);
        OPENSSL_free(pub_key_buf);
    }

    (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);

    if (pkey == NULL) {
        return KONA_BAD;
    }

    EVP_PKEY_CTX* pctx = sm2_create_ctx(pkey);
    if (pctx == NULL) {
        EVP_PKEY_free(pkey);
        return KONA_BAD;
    }

    SM2_CIPHER_CTX* ctx = (SM2_CIPHER_CTX*)OPENSSL_malloc(sizeof(SM2_CIPHER_CTX));
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return KONA_BAD;
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

unsigned char* sm2_encrypt(EVP_PKEY_CTX* ctx, const unsigned char* plaintext, size_t plaintext_len, size_t* ciphertext_len) {
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

    unsigned char* ciphertext = (unsigned char*)OPENSSL_malloc(*ciphertext_len);
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
    unsigned char* ciphertext_buf = sm2_encrypt(ctx->pctx, (const unsigned char*)plaintext_bytes, plaintext_len, &ciphertext_len);
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

unsigned char* sm2_decrypt(EVP_PKEY_CTX* ctx, const unsigned char* ciphertext, size_t ciphertext_len, size_t* cleartext_len) {
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

    unsigned char* cleartext = (unsigned char*)OPENSSL_malloc(*cleartext_len);
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
    unsigned char* cleartext_buf = sm2_decrypt(ctx->pctx, (const unsigned char*)ciphertext_bytes, ciphertext_len, &cleartext_len);
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
/* ***** SM2 cipher end ***** */

/* ***** SM2 signature start ***** */
typedef struct {
    EVP_PKEY* pkey;
    EVP_PKEY_CTX* pctx;
    EVP_MD_CTX* mctx;
} SM2_SIGNATURE_CTX;

SM2_SIGNATURE_CTX* sm2_create_md_ctx(EVP_PKEY* pkey, const unsigned char* id, size_t id_len, int is_sign) {
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
        unsigned char* pub_key_buf = OPENSSL_malloc(SM2_PUB_KEY_LEN);
        if (!pub_key_buf) {
            (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
            (*env)->ReleaseByteArrayElements(env, id, id_bytes, JNI_ABORT);

            return KONA_BAD;
        }

        if (!sm2_gen_pub_key((const unsigned char*)key_bytes, pub_key_buf)) {
            OPENSSL_free(pub_key_buf);
            (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
            (*env)->ReleaseByteArrayElements(env, id, id_bytes, JNI_ABORT);

            return KONA_BAD;
        }

        pkey = load_key_pair((const unsigned char*)key_bytes, pub_key_buf);

        OPENSSL_free(pub_key_buf);
    } else if (key_len == SM2_PUB_KEY_LEN) {
        pkey = load_pub_key((const unsigned char*)key_bytes, key_len);
    } else if (key_len == (SM2_PRI_KEY_LEN + SM2_PUB_KEY_LEN)) {
        unsigned char* pri_key_buf = OPENSSL_malloc(SM2_PRI_KEY_LEN);
        unsigned char* pub_key_buf = OPENSSL_malloc(SM2_PUB_KEY_LEN);
        if (!pri_key_buf || !pub_key_buf) {
            OPENSSL_free(pri_key_buf);
            OPENSSL_free(pub_key_buf);
            (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
            (*env)->ReleaseByteArrayElements(env, id, id_bytes, JNI_ABORT);
            return KONA_BAD;
        }

        memcpy(pri_key_buf, (const unsigned char*)key_bytes, SM2_PRI_KEY_LEN);
        memcpy(pub_key_buf, (const unsigned char*)key_bytes + SM2_PRI_KEY_LEN, SM2_PUB_KEY_LEN);

        pkey = load_key_pair((const unsigned char*)pri_key_buf, pub_key_buf);

        OPENSSL_free(pri_key_buf);
        OPENSSL_free(pub_key_buf);
    }

    if (pkey == NULL) {
        (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, id, id_bytes, JNI_ABORT);
        return KONA_BAD;
    }

    SM2_SIGNATURE_CTX* ctx = sm2_create_md_ctx(pkey, (const unsigned char*)id_bytes, id_len, isSign);

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

unsigned char* sm2_sign(EVP_MD_CTX* ctx, const unsigned char* msg, size_t msg_len, size_t* sig_len) {
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

    unsigned char* sig_buf = (unsigned char*)OPENSSL_malloc(*sig_len);
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
    unsigned char* sig_buf = sm2_sign(ctx->mctx, (unsigned char*)msg_bytes, msg_len, &sig_len);

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

int sm2_verify(EVP_MD_CTX* ctx, const unsigned char* msg, size_t msg_len, const unsigned char* sig, size_t sig_len) {
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

    int verified = sm2_verify(ctx->mctx, (unsigned char*)msg_bytes, msg_len, (unsigned char*)sig_bytes, sig_len)
            ? KONA_GOOD : KONA_BAD;

    (*env)->ReleaseByteArrayElements(env, message, msg_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, sig_bytes, JNI_ABORT);

    return verified;
}
/* ***** SM2 signature end ***** */
