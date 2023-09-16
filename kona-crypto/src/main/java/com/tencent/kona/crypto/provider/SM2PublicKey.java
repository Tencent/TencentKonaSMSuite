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

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

public class SM2PublicKey implements ECPublicKey {

    private static final long serialVersionUID = 682873544399078680L;

    private final byte[] key;
    private final transient ECPoint w;

    public SM2PublicKey(byte[] key) {
        CryptoUtils.checkKey(key);

        this.key = key.clone();
        w = CryptoUtils.pubKeyPoint(key);
    }

    public SM2PublicKey(ECPoint w) {
        CryptoUtils.checkKey(w);

        this.w = w;
        key = CryptoUtils.pubKey(w);
    }

    public SM2PublicKey(ECPublicKey ecPublicKey) {
        this(ecPublicKey.getW());
    }

    @Override
    public String getAlgorithm() {
        return "SM2";
    }

    /**
     * Uncompressed EC point: 0x04||X||Y
     */
    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return key.clone();
    }

    @Override
    public ECPoint getW() {
        return w;
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
        SM2PublicKey that = (SM2PublicKey) o;
        return Arrays.equals(key, that.key);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(key);
    }
}
