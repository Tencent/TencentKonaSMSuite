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
import com.tencent.kona.jdk.internal.util.Preconditions;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

public final class SM3OneShotHMac extends MacSpi implements Cloneable {

    private final ByteArrayWriter buffer = new ByteArrayWriter();

    private byte[] key;

    @Override
    protected int engineGetMacLength() {
        return Constants.SM3_HMAC_LEN;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.key = null;
        buffer.reset();

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

        this.key = secret;
    }

    @Override
    protected void engineUpdate(byte input) {
        buffer.write(new byte[] { input });
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
    protected byte[] engineDoFinal() {
        byte[] mac = NativeCrypto.sm3hmacOneShotMac(key, buffer.toByteArray());
        buffer.reset();
        return mac;
    }

    @Override
    protected void engineReset() {
        buffer.reset();
    }

    @Override
    public SM3OneShotHMac clone() throws CloneNotSupportedException {
        SM3OneShotHMac clone = new SM3OneShotHMac();
        clone.key = key == null ? null : key.clone();
        clone.buffer.write(buffer.toByteArray());
        return clone;
    }
}
