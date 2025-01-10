/*
 * Copyright (C) 2024, 2025, THL A29 Limited, a Tencent company. All rights reserved.
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

import com.tencent.kona.crypto.util.Constants;
import com.tencent.kona.crypto.util.Sweeper;
import com.tencent.kona.jdk.internal.util.Preconditions;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

public final class SM3HMac extends MacSpi implements Cloneable {

    private static final Sweeper SWEEPER = Sweeper.instance();

    private NativeSM3HMac sm3HMac;

    @Override
    protected int engineGetMacLength() {
        return Constants.SM3_HMAC_LEN;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("No need parameters");
        }

        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("SecretKey is expected");
        }

        byte[] secret = key.getEncoded();
        if (secret == null) {
            throw new InvalidKeyException("No key data");
        }

        sm3HMac = new NativeSM3HMac(secret);

        SWEEPER.register(this, new SweepNativeRef(sm3HMac));
    }

    @Override
    protected void engineUpdate(byte input) {
        sm3HMac.update(new byte[] { input });
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
        sm3HMac.update(data);
    }

    @Override
    protected byte[] engineDoFinal() {
        return sm3HMac.doFinal();
    }

    @Override
    protected void engineReset() {
        sm3HMac.reset();
    }

    @Override
    public SM3HMac clone() throws CloneNotSupportedException {
        SM3HMac clone = (SM3HMac) super.clone();
        clone.sm3HMac = sm3HMac.clone();
        return clone;
    }
}
