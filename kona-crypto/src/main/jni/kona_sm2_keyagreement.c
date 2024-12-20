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
#include <stdbool.h>
#include <math.h>

#include <jni.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#include "kona/kona_common.h"
#include "kona/kona_sm2.h"
#include "kona/kona_sm3.h"

SM2_KEYEX_CTX* sm2_create_keyex_ctx() {
    EVP_MD_CTX* sm3_ctx = sm3_create_ctx();
    if (sm3_ctx == NULL) {
        return NULL;
    }

    BN_CTX* bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        return NULL;
    }

    SM2_KEYEX_CTX* ctx = OPENSSL_malloc(sizeof(SM2_KEYEX_CTX));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->sm3_ctx = sm3_ctx;
    ctx->bn_ctx = bn_ctx;

    return ctx;
}

void sm2_free_keyex_ctx(SM2_KEYEX_CTX* ctx) {
    if (ctx != NULL) {
        if (ctx->sm3_ctx != NULL) EVP_MD_CTX_free(ctx->sm3_ctx);
        if (ctx->bn_ctx != NULL) BN_CTX_free(ctx->bn_ctx);

        OPENSSL_free(ctx);
    }
}

int z(uint8_t* out, SM2_KEYEX_CTX* ctx,
       const uint8_t* id, const size_t id_len,
       const EC_GROUP* group, const EC_POINT* point) {
    const SM2_ID* default_id = sm2_id();
    const SM2_CURVE* curve = sm2_curve();

    const uint8_t* id_to_use = id ? id : default_id->id;
    size_t id_bytes_len = id ? id_len : default_id->id_len;
    int id_bits_len = id_bytes_len << 3;

    uint8_t id_len_high = (id_bits_len >> 8) & 0xFF;
    uint8_t id_len_low = id_bits_len & 0xFF;
    if (!EVP_DigestUpdate(ctx->sm3_ctx, &id_len_high, 1) ||
        !EVP_DigestUpdate(ctx->sm3_ctx, &id_len_low, 1) ||
        !EVP_DigestUpdate(ctx->sm3_ctx, id_to_use, id_bytes_len) ||

        !EVP_DigestUpdate(ctx->sm3_ctx, curve->a, curve->a_len) ||
        !EVP_DigestUpdate(ctx->sm3_ctx, curve->b, curve->b_len) ||

        !EVP_DigestUpdate(ctx->sm3_ctx, curve->gen_x, curve->gen_x_len) ||
        !EVP_DigestUpdate(ctx->sm3_ctx, curve->gen_y, curve->gen_y_len)) {
        return OPENSSL_FAILURE;
    }

    BIGNUM* x_bn = BN_new();
    BIGNUM* y_bn = BN_new();
    if (x_bn == NULL || y_bn == NULL) {
        return OPENSSL_FAILURE;
    }

    if (!EC_POINT_get_affine_coordinates(group, point, x_bn, y_bn, ctx->bn_ctx)) {
        BN_free(x_bn);
        BN_free(y_bn);
        return OPENSSL_FAILURE;
    }

    uint8_t x_bytes[32];
    uint8_t y_bytes[32];
    if (!BN_bn2binpad(x_bn, x_bytes, sizeof(x_bytes)) ||
        !BN_bn2binpad(y_bn, y_bytes, sizeof(y_bytes))) {
        return OPENSSL_FAILURE;
    }

    if (!EVP_DigestUpdate(ctx->sm3_ctx, x_bytes, sizeof(x_bytes)) ||
        !EVP_DigestUpdate(ctx->sm3_ctx, y_bytes, sizeof(y_bytes))) {
        return OPENSSL_FAILURE;
    }

    int len = EVP_DigestFinal_ex(ctx->sm3_ctx, out, NULL);
    if (!sm3_reset(ctx->sm3_ctx)) {
        return OPENSSL_FAILURE;
    }

    BN_free(x_bn);
    BN_free(y_bn);

    return len;
}

int kdf(uint8_t* key_out, const int key_len, EVP_MD_CTX* sm3_ctx, const uint8_t* in, size_t in_len) {
    int remainder = key_len % SM3_DIGEST_LEN;
    int count = key_len / SM3_DIGEST_LEN + (remainder == 0 ? 0 : 1);

    for (int i = 1; i <= count; i++) {
        uint8_t digest[SM3_DIGEST_LEN];
        if (!EVP_DigestUpdate(sm3_ctx, in, in_len)) {
            return OPENSSL_FAILURE;
        }

        uint8_t counter[4] = { (i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF };
        if (!EVP_DigestUpdate(sm3_ctx, counter, 4) ||
            !EVP_DigestFinal_ex(sm3_ctx, digest, NULL) |
            !sm3_reset(sm3_ctx)) {
            return OPENSSL_FAILURE;
        }

        int length = (i == count && remainder != 0) ? remainder : SM3_DIGEST_LEN;
        memcpy(key_out + (i - 1) * SM3_DIGEST_LEN, digest, length);
    }

    return OPENSSL_SUCCESS;
}

void combine(uint8_t* combined_out,
             const uint8_t* vX, const uint8_t* vY,
             const uint8_t* zA, const uint8_t* zB,
             const bool is_initiator) {
    memcpy(combined_out, vX, 32);
    memcpy(combined_out + 32, vY, 32);

    if (is_initiator) {
        memcpy(combined_out + 32 + 32, zA, 32);
        memcpy(combined_out + 32 + 32 + 32, zB, 32);
    } else {
        memcpy(combined_out + 32 + 32, zB, 32);
        memcpy(combined_out + 32 + 32 + 32, zA, 32);
    }
}

int calc_bar(BIGNUM* x, BIGNUM* two_pow_w, BIGNUM* two_pow_w_sub_one) {
    return BN_mask_bits(x, BN_num_bits(two_pow_w_sub_one)) && BN_add(x, two_pow_w, x);
}

int sm2_derive_key(uint8_t* key_out, int key_len,
                   SM2_KEYEX_CTX* ctx, const SM2_KEYEX_PARAMS* params, bool is_initiator) {
    const EC_GROUP* group = sm2_group();
    if (group == NULL) {
        return OPENSSL_FAILURE;
    }

    BIGNUM* order = BN_new();
    BIGNUM* order_minus_one = BN_new();
    BIGNUM* two_pow_w = BN_new();
    BIGNUM* two_pow_w_sub_one = BN_new();
    BIGNUM* x1 = BN_new();
    BIGNUM* tA = BN_new();
    BIGNUM* x2 = BN_new();
    BIGNUM* cofactor = BN_new();
    BIGNUM* vX_bn = BN_new();
    BIGNUM* vY_bn = BN_new();
    EC_POINT* rA_p = NULL;
    EC_POINT* interim_p = NULL;
    EC_POINT* u_p = NULL;
    uint8_t* zA = NULL;
    uint8_t* zB = NULL;
    uint8_t* combined = NULL;
    int ret = OPENSSL_FAILURE;

    if (order == NULL || order_minus_one == NULL || two_pow_w == NULL || two_pow_w_sub_one == NULL ||
        x1 == NULL || tA == NULL || x2 == NULL || cofactor == NULL || vX_bn == NULL || vY_bn == NULL) {
        goto cleanup;
    }

    if (!EC_GROUP_get_order(group, order, ctx->bn_ctx)) {
        goto cleanup;
    }

    if (!BN_sub(order_minus_one, order, BN_value_one())) {
        goto cleanup;
    }

    int bit_length = BN_num_bits(order_minus_one);
    int w = (int)ceil((double)bit_length / 2) - 1;

    if (!BN_lshift(two_pow_w, BN_value_one(), w) ||
        !BN_sub(two_pow_w_sub_one, two_pow_w, BN_value_one())) {
        goto cleanup;
    }

    const BIGNUM* rA = params->e_pri_key;

    rA_p = EC_POINT_new(group);
    if (rA_p == NULL || !EC_POINT_mul(group, rA_p, rA, NULL, NULL, ctx->bn_ctx)) {
        goto cleanup;
    }

    if (!EC_POINT_get_affine_coordinates(group, rA_p, x1, NULL, ctx->bn_ctx) ||
        !calc_bar(x1, two_pow_w, two_pow_w_sub_one)) {
        goto cleanup;
    }

    if (!BN_mul(x1, x1, rA, ctx->bn_ctx) ||
        !BN_add(x1, x1, params->pri_key) ||
        !BN_mod(tA, x1, order, ctx->bn_ctx)) {
        goto cleanup;
    }

    if (!EC_POINT_get_affine_coordinates(group, params->peer_e_pub_key, x2, NULL, ctx->bn_ctx) ||
        !calc_bar(x2, two_pow_w, two_pow_w_sub_one)) {
        goto cleanup;
    }

    interim_p = EC_POINT_new(group);
    if (interim_p == NULL || !EC_POINT_mul(group, interim_p, NULL, params->peer_e_pub_key, x2, ctx->bn_ctx) ||
        !EC_POINT_add(group, interim_p, interim_p, params->peer_pub_key, ctx->bn_ctx)) {
        goto cleanup;
    }

    if (!EC_GROUP_get_cofactor(group, cofactor, ctx->bn_ctx)) {
        goto cleanup;
    }

    u_p = EC_POINT_new(group);
    if (u_p == NULL ||
        !BN_mul(tA, tA, cofactor, ctx->bn_ctx) ||
        !EC_POINT_mul(group, u_p, NULL, interim_p, tA, ctx->bn_ctx)) {
        goto cleanup;
    }

    if (EC_POINT_is_at_infinity(group, u_p)) {
        goto cleanup;
    }

    if (!EC_POINT_get_affine_coordinates(group, u_p, vX_bn, vY_bn, ctx->bn_ctx)) {
        goto cleanup;
    }

    int vX_len = BN_num_bytes(vX_bn);
    int vY_len = BN_num_bytes(vY_bn);
    if (vX_len > 32 || vY_len > 32) {
        goto cleanup;
    }

    uint8_t vX[32] = {0};
    uint8_t vY[32] = {0};
    if (!BN_bn2bin(vX_bn, vX + (32 - vX_len)) ||
        !BN_bn2bin(vY_bn, vY + (32 - vY_len))) {
        goto cleanup;
    }

    zA = OPENSSL_malloc(32);
    zB = OPENSSL_malloc(32);
    if (zA == NULL || zB == NULL ||
        !z(zA, ctx, params->id, params->id_len, group, params->pub_key) ||
        !z(zB, ctx, params->peer_id, params->peer_id_len, group, params->peer_pub_key)) {
        goto cleanup;
    }

    combined = OPENSSL_malloc(128);
    if (combined == NULL) {
        goto cleanup;
    }
    combine(combined, vX, vY, zA, zB, is_initiator);

    if (!kdf(key_out, key_len, ctx->sm3_ctx, combined, 128)) {
        goto cleanup;
    }

    ret = OPENSSL_SUCCESS;

    cleanup:
    BN_free(order);
    BN_free(order_minus_one);
    BN_free(two_pow_w);
    BN_free(two_pow_w_sub_one);
    BN_free(x1);
    BN_free(tA);
    BN_free(x2);
    BN_free(cofactor);
    BN_free(vX_bn);
    BN_free(vY_bn);
    EC_POINT_free(rA_p);
    EC_POINT_free(interim_p);
    EC_POINT_free(u_p);
    OPENSSL_free(zA);
    OPENSSL_free(zB);
    OPENSSL_free(combined);

    return ret;
}

void sm2_keyex_params_free(SM2_KEYEX_PARAMS* ctx) {
    if (ctx != NULL) {
        if (ctx->pri_key != NULL) BN_free(ctx->pri_key);
        if (ctx->pub_key != NULL) EC_POINT_free(ctx->pub_key);
        if (ctx->e_pri_key != NULL) BN_free(ctx->e_pri_key);
        if (ctx->id != NULL) OPENSSL_free(ctx->id);

        if (ctx->peer_pub_key != NULL) EC_POINT_free(ctx->peer_pub_key);
        if (ctx->peer_e_pub_key != NULL) EC_POINT_free(ctx->peer_e_pub_key);
        if (ctx->peer_id != NULL) OPENSSL_free(ctx->peer_id);

        OPENSSL_free(ctx);
    }
}

JNIEXPORT jlong JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2KeyExCreateCtx
  (JNIEnv* env, jobject thisObj) {
    return (jlong)sm2_create_keyex_ctx();
}

JNIEXPORT void JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2KeyExFreeCtx
  (JNIEnv* env, jobject thisObj, jlong pointer) {
    return sm2_free_keyex_ctx((SM2_KEYEX_CTX*) pointer);
}

JNIEXPORT jbyteArray JNICALL Java_com_tencent_kona_crypto_provider_nativeImpl_NativeCrypto_sm2DeriveKey
  (JNIEnv* env, jobject thisObj, jlong pointer,
   jbyteArray priKey, jbyteArray pubKey, jbyteArray ePriKey, jbyteArray id,
   jbyteArray peerPubKey, jbyteArray peerEPubKey, jbyteArray peerId,
   jboolean isInitiator, jint sharedKeyLength) {
    SM2_KEYEX_CTX* ctx = (SM2_KEYEX_CTX*)pointer;
    if (ctx == NULL) {
        return NULL;
    }

    jbyte* pri_key_bytes = NULL;
    jbyte* pub_key_bytes = NULL;
    jbyte* e_pri_key_bytes = NULL;
    jbyte* id_bytes = NULL;
    jbyte* peer_pub_key_bytes = NULL;
    jbyte* peer_e_pub_key_bytes = NULL;
    jbyte* peer_id_bytes = NULL;
    BIGNUM* pri_key = NULL;
    EC_POINT* pub_key = NULL;
    BIGNUM* e_pri_key = NULL;
    EC_POINT* peer_pub_key = NULL;
    EC_POINT* peer_e_pub_key = NULL;
    SM2_KEYEX_PARAMS* params = NULL;
    uint8_t* shared_key_buf = NULL;
    jbyteArray shared_key_bytes = NULL;

    int pri_key_len = (*env)->GetArrayLength(env, priKey);
    if (pri_key_len != SM2_PRI_KEY_LEN) {
        goto cleanup;
    }
    pri_key_bytes = (*env)->GetByteArrayElements(env, priKey, NULL);
    if (pri_key_bytes == NULL) {
        goto cleanup;
    }

    int pub_key_len = (*env)->GetArrayLength(env, pubKey);
    if (pub_key_len != SM2_PUB_KEY_LEN) {
        goto cleanup;
    }
    pub_key_bytes = (*env)->GetByteArrayElements(env, pubKey, NULL);
    if (pub_key_bytes == NULL) {
        goto cleanup;
    }

    int e_pri_key_len = (*env)->GetArrayLength(env, ePriKey);
    if (e_pri_key_len != SM2_PRI_KEY_LEN) {
        goto cleanup;
    }
    e_pri_key_bytes = (*env)->GetByteArrayElements(env, ePriKey, NULL);
    if (e_pri_key_bytes == NULL) {
        goto cleanup;
    }

    int id_len = (*env)->GetArrayLength(env, id);
    if (id_len <= 0) {
        goto cleanup;
    }
    id_bytes = (*env)->GetByteArrayElements(env, id, NULL);
    if (id_bytes == NULL) {
        goto cleanup;
    }

    int peer_pub_key_len = (*env)->GetArrayLength(env, peerPubKey);
    if (peer_pub_key_len != SM2_PUB_KEY_LEN) {
        goto cleanup;
    }
    peer_pub_key_bytes = (*env)->GetByteArrayElements(env, peerPubKey, NULL);
    if (peer_pub_key_bytes == NULL) {
        goto cleanup;
    }

    int peer_e_pub_key_len = (*env)->GetArrayLength(env, peerEPubKey);
    if (peer_e_pub_key_len != SM2_PUB_KEY_LEN) {
        goto cleanup;
    }
    peer_e_pub_key_bytes = (*env)->GetByteArrayElements(env, peerEPubKey, NULL);
    if (peer_e_pub_key_bytes == NULL) {
        goto cleanup;
    }

    int peer_id_len = (*env)->GetArrayLength(env, peerId);
    if (peer_id_len <= 0) {
        goto cleanup;
    }
    peer_id_bytes = (*env)->GetByteArrayElements(env, peerId, NULL);
    if (peer_id_bytes == NULL) {
        goto cleanup;
    }

    bool is_initiator = (bool)isInitiator;

    int shared_key_len = (int)sharedKeyLength;
    if (shared_key_len <= 0) {
        goto cleanup;
    }

    pri_key = sm2_pri_key((const uint8_t *)pri_key_bytes);
    if (pri_key == NULL) {
        goto cleanup;
    }

    pub_key = sm2_pub_key((const uint8_t *)pub_key_bytes, pub_key_len);
    if (pub_key == NULL) {
        goto cleanup;
    }

    e_pri_key = sm2_pri_key((const uint8_t *)e_pri_key_bytes);
        if (e_pri_key == NULL) {
            goto cleanup;
        }

        peer_pub_key = sm2_pub_key((const uint8_t *)peer_pub_key_bytes, peer_pub_key_len);
        if (peer_pub_key == NULL) {
            goto cleanup;
        }

        peer_e_pub_key = sm2_pub_key((const uint8_t *)peer_e_pub_key_bytes, peer_e_pub_key_len);
        if (peer_e_pub_key == NULL) {
            goto cleanup;
        }

        params = OPENSSL_malloc(sizeof(SM2_KEYEX_PARAMS));
        if (params == NULL) {
            goto cleanup;
        }
        params->pri_key = pri_key;
        params->pub_key = pub_key;
        params->e_pri_key = e_pri_key;
        params->id = (uint8_t*)id_bytes;
        params->id_len = id_len;
        params->peer_pub_key = peer_pub_key;
        params->peer_e_pub_key = peer_e_pub_key;
        params->peer_id = (uint8_t*)peer_id_bytes;
        params->peer_id_len = peer_id_len;

        shared_key_buf = OPENSSL_malloc(shared_key_len);
        if (shared_key_buf == NULL) {
            goto cleanup;
        }

        if (!sm2_derive_key(shared_key_buf, shared_key_len, ctx, params, is_initiator)) {
            goto cleanup;
        }

        shared_key_bytes = (*env)->NewByteArray(env, shared_key_len);
        if (shared_key_bytes == NULL) {
            goto cleanup;
        }
        (*env)->SetByteArrayRegion(env, shared_key_bytes, 0, shared_key_len, (jbyte*)shared_key_buf);

    cleanup:
        if (pri_key_bytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, priKey, pri_key_bytes, JNI_ABORT);
        }
        if (pub_key_bytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, pubKey, pub_key_bytes, JNI_ABORT);
        }
        if (e_pri_key_bytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, ePriKey, e_pri_key_bytes, JNI_ABORT);
        }
        if (id_bytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, id, id_bytes, JNI_ABORT);
        }
        if (peer_pub_key_bytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, peerPubKey, peer_pub_key_bytes, JNI_ABORT);
        }
        if (peer_e_pub_key_bytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, peerEPubKey, peer_e_pub_key_bytes, JNI_ABORT);
        }
        if (peer_id_bytes != NULL) {
            (*env)->ReleaseByteArrayElements(env, peerId, peer_id_bytes, JNI_ABORT);
        }
        BN_free(pri_key);
        EC_POINT_free(pub_key);
        BN_free(e_pri_key);
        EC_POINT_free(peer_pub_key);
        EC_POINT_free(peer_e_pub_key);
        OPENSSL_free(params);
        OPENSSL_free(shared_key_buf);

        return shared_key_bytes;
}
