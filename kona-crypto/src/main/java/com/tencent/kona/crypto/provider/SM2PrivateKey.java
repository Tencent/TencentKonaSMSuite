/*
 * Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
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

import com.tencent.kona.crypto.spec.SM2ParameterSpec;
import com.tencent.kona.crypto.CryptoUtils;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;

public class SM2PrivateKey implements ECPrivateKey {

    private static final long serialVersionUID = 8891019868158427133L;

    private final BigInteger keyS;
    private final byte[] key;

    public SM2PrivateKey(byte[] key) {
        CryptoUtils.checkKey(key);

        keyS = CryptoUtils.toBigInt(key);
        this.key = CryptoUtils.priKey(keyS);
    }

    public SM2PrivateKey(BigInteger keyS) {
        CryptoUtils.checkKey(keyS);

        this.keyS = keyS;
        key = CryptoUtils.priKey(keyS);
    }

    public SM2PrivateKey(ECPrivateKey ecPrivateKey) {
        this(ecPrivateKey.getS());
    }

    @Override
    public String getAlgorithm() {
        return "SM2";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return key.clone();
    }

    @Override
    public BigInteger getS() {
        return keyS;
    }

    @Override
    public ECParameterSpec getParams() {
        return SM2ParameterSpec.instance();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        SM2PrivateKey that = (SM2PrivateKey) o;
        return Arrays.equals(key, that.key);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(key);
    }
}
