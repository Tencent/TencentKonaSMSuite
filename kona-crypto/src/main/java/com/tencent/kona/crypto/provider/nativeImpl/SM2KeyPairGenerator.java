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

import com.tencent.kona.crypto.CryptoUtils;
import com.tencent.kona.crypto.provider.SM2PrivateKey;
import com.tencent.kona.crypto.provider.SM2PublicKey;
import com.tencent.kona.crypto.spec.SM2ParameterSpec;
import com.tencent.kona.crypto.util.Sweeper;
import com.tencent.kona.sun.security.util.KnownOIDs;
import com.tencent.kona.sun.security.util.NamedCurve;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import static com.tencent.kona.crypto.util.Constants.*;

public final class SM2KeyPairGenerator extends KeyPairGenerator {

    private static final Sweeper SWEEPER = Sweeper.instance();

    private final NativeSM2KeyPairGen sm2;

    public SM2KeyPairGenerator() {
        super("SM2");
        sm2 = new NativeSM2KeyPairGen();

        SWEEPER.register(this, new SweepNativeRef(sm2));
    }

    @Override
    public void initialize(int keySize, SecureRandom random) {
        if (keySize != SM2_PRIKEY_LEN << 3) {
            throw new IllegalArgumentException(
                    "keySize must be 256-bit: " + keySize);
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) {
        if (params == null || !(params instanceof SM2ParameterSpec)
                && !KnownOIDs.curveSM2.value().equals(
                ((NamedCurve) params).getObjectId())) {
            throw new IllegalArgumentException(
                    "params must be SM2ParameterSpec or NamedCurve (curveSM2)");
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[] keyPair = sm2.genKeyPair();
        ECPrivateKey priKey = new SM2PrivateKey(
                CryptoUtils.copy(keyPair, 0, SM2_PRIKEY_LEN));
        ECPublicKey pubKey = new SM2PublicKey(
                CryptoUtils.copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN));

        return new KeyPair(pubKey, priKey);
    }
}
