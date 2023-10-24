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

    private final byte[] encoded;
    private final transient ECPoint pubPoint;

    public SM2PublicKey(byte[] encoded) {
        if (encoded == null || encoded.length == 0) {
            throw new IllegalArgumentException("Missing encoded public key");
        }

        pubPoint = CryptoUtils.pubKeyPoint(encoded);
        this.encoded = encoded.clone();
    }

    public SM2PublicKey(ECPoint pubPoint) {
        if (pubPoint == null) {
            throw new IllegalArgumentException("Missing public key");
        }

        if (pubPoint.equals(ECPoint.POINT_INFINITY)) {
            throw new IllegalArgumentException(
                    "Public point cannot be infinite point");
        }

        encoded = CryptoUtils.pubKey(pubPoint);
        this.pubPoint = pubPoint;
    }

    public SM2PublicKey(ECPublicKey ecPublicKey) {
        this(ecPublicKey.getW());
    }

    @Override
    public String getAlgorithm() {
        return "SM2";
    }

    /**
     * Uncompressed EC point: 0x04||x||y
     */
    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return encoded.clone();
    }

    @Override
    public ECPoint getW() {
        return pubPoint;
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
        return Arrays.equals(encoded, that.encoded);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encoded);
    }
}
