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
import com.tencent.kona.crypto.util.Constants;
import com.tencent.kona.sun.security.ec.point.Point;
import com.tencent.kona.sun.security.jca.JCAUtil;
import com.tencent.kona.sun.security.util.ArrayUtil;
import com.tencent.kona.sun.security.util.KnownOIDs;
import com.tencent.kona.sun.security.util.NamedCurve;

import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

import static com.tencent.kona.sun.security.ec.ECOperations.SM2OPS;
import static com.tencent.kona.sun.security.ec.ECOperations.toECPoint;

public final class SM2KeyPairGenerator extends KeyPairGeneratorSpi {

    private SecureRandom random;

    @Override
    public void initialize(int keySize, SecureRandom random) {
        if (keySize != Constants.SM2_PRIKEY_LEN << 3) {
            throw new IllegalArgumentException(
                    "keySize must be 256-bit: " + keySize);
        }

        this.random = random;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) {
        if (params == null || !(params instanceof SM2ParameterSpec)
                && !KnownOIDs.curveSM2.value().equals(
                        ((NamedCurve) params).getObjectId())) {
            throw new IllegalArgumentException(
                    "params must be SM2ParameterSpec or NamedCurve (curveSM2)");
        }

        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair() {
        if (random == null) {
            random = JCAUtil.getSecureRandom();
        }

        byte[] privArr = SM2OPS.generatePrivateScalar(random);
        Point point = SM2OPS.multiply(
                SM2ParameterSpec.instance().getGenerator(), privArr);
        ECPoint w = toECPoint(point);
        PublicKey publicKey = new SM2PublicKey(w);

        // Convert little-endian to big-endian
        ArrayUtil.reverse(privArr);
        PrivateKey privateKey = new SM2PrivateKey(privArr);
        Arrays.fill(privArr, (byte)0);

        return new KeyPair(publicKey, privateKey);
    }
}
