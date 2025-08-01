/*
 * Copyright (C) 2022, 2023, Tencent. All rights reserved.
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

package com.tencent.kona.crypto.provider;

import static com.tencent.kona.crypto.CryptoUtils.bytes8ToLong;

/**
 * The abstract implementation on the Galois Field multiplication.
 */
abstract class GFMultiplier {

    final long[] subkeyWords = new long[2];

    // Convert key from 16-bytes to 2-longs
    GFMultiplier(byte[] subkeyH) {
        subkeyWords[0] = bytes8ToLong(subkeyH, 0);
        subkeyWords[1] = bytes8ToLong(subkeyH, 8);
    }

    abstract void multiply(long[] block);
}
