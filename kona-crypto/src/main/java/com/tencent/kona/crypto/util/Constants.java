/*
 * Copyright (C) 2022, 2024, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. THL A29 Limited designates
 * this particular file as subject to the "Classpath" exception as provided
 * in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package com.tencent.kona.crypto.util;

import com.tencent.kona.crypto.CryptoUtils;

import java.math.BigInteger;

public final class Constants {

    public static final BigInteger TWO = BigInteger.valueOf(2);
    public static final BigInteger THREE = BigInteger.valueOf(3);

    public static final String JDK_VERSION = CryptoUtils.privilegedGetProperty(
            "java.specification.version");

    public static final String JDK_VENDOR = CryptoUtils.privilegedGetProperty(
            "java.specification.vendor");

    // The length of uncompressed SM2 public key,
    // exactly an EC point's coordinates (x, y).
    // The hex format is 04||x||y
    public static final int SM2_PUBKEY_LEN = 65;

    // The length of the affine coordinate.
    public static final int SM2_PUBKEY_AFFINE_LEN = 32;

    public static final int SM2_CURVE_FIELD_SIZE = 32;

    public static final int SM2_PRIKEY_LEN = 32;

    public static final int SM3_BLOCK_SIZE = 64;
    public static final int SM3_DIGEST_LEN = 32;
    public static final int SM3_HMAC_LEN = 32;

    public static final int SM4_BLOCK_SIZE = 16;
    public static final int SM4_KEY_SIZE = 16;
    public static final int SM4_IV_LEN = 16;
    public static final int SM4_GCM_IV_LEN = 12;
    public static final int SM4_GCM_TAG_LEN = 16;

    // The default ID 1234567812345678
    private static final byte[] DEFAULT_ID = new byte[] {
            49, 50, 51, 52, 53, 54, 55, 56,
            49, 50, 51, 52, 53, 54, 55, 56};

    public static byte[] defaultId() {
        return DEFAULT_ID.clone();
    }
}
