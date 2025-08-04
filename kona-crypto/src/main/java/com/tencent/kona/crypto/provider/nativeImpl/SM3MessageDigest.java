/*
 * Copyright (C) 2024, Tencent. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. Tencent designates
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

import com.tencent.kona.crypto.util.Sweeper;
import com.tencent.kona.jdk.internal.util.Preconditions;

import java.security.MessageDigest;

import static com.tencent.kona.crypto.util.Constants.SM3_DIGEST_LEN;

public final class SM3MessageDigest extends MessageDigest implements Cloneable {

    private static final Sweeper SWEEPER = Sweeper.instance();

    private NativeSM3 sm3;

    public SM3MessageDigest() {
        super("SM3");
        sm3 = new NativeSM3();

        SWEEPER.register(this, new SweepNativeRef(sm3));
    }

    @Override
    protected void engineUpdate(byte input) {
        sm3.update(new byte[] { input });
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

        byte[] data = new byte[len];
        System.arraycopy(input, offset, data, 0, len);
        sm3.update(data);
    }

    @Override
    protected byte[] engineDigest() {
        return sm3.doFinal();
    }

    @Override
    protected void engineReset() {
        sm3.reset();
    }

    @Override
    public SM3MessageDigest clone() throws CloneNotSupportedException {
        SM3MessageDigest clone = (SM3MessageDigest) super.clone();
        clone.sm3 = sm3.clone();
        return clone;
    }
}
