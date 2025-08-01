/*
 * Copyright (C) 2024, 2025, Tencent. All rights reserved.
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

package com.tencent.kona.crypto.provider.nativeImpl;

import com.tencent.kona.jdk.internal.util.Preconditions;

import java.security.MessageDigest;

import static com.tencent.kona.crypto.util.Constants.SM3_DIGEST_LEN;

public final class SM3OneShotMessageDigest extends MessageDigest implements Cloneable {

    private final ByteArrayWriter buffer = new ByteArrayWriter();

    public SM3OneShotMessageDigest() {
        super("SM3");
    }

    @Override
    protected void engineUpdate(byte input) {
        buffer.write(new byte[] { input });
    }

    @Override
    protected int engineGetDigestLength() {
        return SM3_DIGEST_LEN;
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (len == 0) {
            return;
        }
        Preconditions.checkFromIndexSize(
                offset, len, input.length, Preconditions.AIOOBE_FORMATTER);

        buffer.write(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        byte[] digest = NativeCrypto.sm3OneShotDigest(buffer.toByteArray());
        buffer.reset();
        return digest;
    }

    @Override
    protected void engineReset() {
        buffer.reset();
    }

    @Override
    public SM3OneShotMessageDigest clone() throws CloneNotSupportedException {
        SM3OneShotMessageDigest clone = new SM3OneShotMessageDigest();
        clone.buffer.write(buffer.toByteArray());
        return clone;
    }
}
