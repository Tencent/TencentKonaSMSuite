/*
 * Copyright (C) 2024, Tencent. All rights reserved.
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

#include <openssl/evp.h>

#include "kona/kona_common.h"

EVP_MAC* hmac();

EVP_MD_CTX* sm3_create_ctx();
int sm3_reset(EVP_MD_CTX* ctx);

EVP_MAC_CTX* sm3hmac_create_ctx(EVP_MAC* mac, const uint8_t* key, size_t key_len);
int sm3hmac_reset(EVP_MAC_CTX* ctx);
