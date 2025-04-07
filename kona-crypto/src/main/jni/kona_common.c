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

#include <string.h>

#include <jni.h>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include "kona/kona_common.h"
#include "kona/kona_ec.h"

static const int supported_curves[] = {
        NID_X9_62_prime256v1,
        NID_secp384r1,
        NID_secp521r1,
        NID_sm2
};

static EVP_PKEY *cached_params[sizeof(supported_curves)/sizeof(int)];

void ec_init_param_cache() {
    for (size_t i = 0; i < sizeof(supported_curves)/sizeof(int); i++) {
        cached_params[i] = ec_gen_param(supported_curves[i]);
    }
}

EVP_PKEY* ec_get_cached_param(int curve_nid) {
    for (size_t i = 0; i < sizeof(supported_curves)/sizeof(int); i++) {
        if (supported_curves[i] == curve_nid) {
            return cached_params[i];
        }
    }

    return NULL;
}

void ec_param_cache_free() {
    for (size_t i = 0; i < sizeof(supported_curves)/sizeof(int); i++) {
        if (cached_params[i]) {
            EVP_PKEY_free(cached_params[i]);
            cached_params[i] = NULL;
        }
    }
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    ec_init_param_cache();

    return JNI_VERSION_1_8;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    ec_param_cache_free();
}

uint8_t* bn2bin(BIGNUM* bn) {
    int bn_size = BN_num_bytes(bn);
    if (bn_size <= 0) {
        return NULL;
    }

    uint8_t* bn_bytes = (uint8_t*)OPENSSL_malloc(bn_size);
    if (BN_bn2bin(bn, bn_bytes) != bn_size) {
        return NULL;
    }

    return bn_bytes;
}

const char* hex_digits = "0123456789abcdef";
void bin2hex(const uint8_t* bytes, size_t offset, size_t len, uint8_t* hex) {
    for (size_t i = 0; i < len; i++) {
        hex[i * 2] = hex_digits[bytes[i + offset] / 16];
        hex[i * 2 + 1] = hex_digits[bytes[i + offset] % 16];
    }

    hex[len * 2] = '\0';
}

int hexchar2int(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else {
        return -1;
    }
}

uint8_t* hex2bin(const char* hex) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        return NULL;
    }

    size_t bytes_len = hex_len / 2;
    uint8_t* bytes = (uint8_t*)OPENSSL_malloc(bytes_len);
    if (bytes == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < bytes_len; i++) {
        int high_nibble = hexchar2int(hex[2 * i]);
        int low_nibble = hexchar2int(hex[2 * i + 1]);

        if (high_nibble == -1 || low_nibble == -1) {
            OPENSSL_free(bytes);
            return NULL;
        }

        bytes[i] = (high_nibble << 4) | low_nibble;
    }

    return bytes;
}

void print_hex(const uint8_t* bytes, size_t offset, size_t len) {
    uint8_t* hex = OPENSSL_malloc(len* 2 + 1);
    bin2hex(bytes, offset, len, hex);
    KONA_print("%s", hex);
    OPENSSL_free(hex);
}
