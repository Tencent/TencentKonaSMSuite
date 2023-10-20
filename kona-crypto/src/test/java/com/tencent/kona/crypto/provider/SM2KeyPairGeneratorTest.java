/*
 * Copyright (C) 2023, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.TestUtils;
import com.tencent.kona.crypto.spec.SM2ParameterSpec;
import com.tencent.kona.sun.security.util.CurveDB;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static com.tencent.kona.crypto.util.Constants.SM2_PRIKEY_LEN;
import static com.tencent.kona.crypto.util.Constants.SM2_PUBKEY_LEN;

/**
 * The test for SM2 key pair generation.
 */
public class SM2KeyPairGeneratorTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testInitialize() throws Exception {
        KeyPairGenerator keyPairGen
                = KeyPairGenerator.getInstance("SM2", PROVIDER);

        keyPairGen.initialize(256);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> keyPairGen.initialize(128));

        keyPairGen.initialize(SM2ParameterSpec.instance());
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> keyPairGen.initialize(CurveDB.P_256));
        Assertions.assertThrows(NullPointerException.class,
                () -> keyPairGen.initialize(null));
    }

    @Test
    public void testKeyPairGen() throws Exception {
        KeyPairGenerator keyPairGen
                = KeyPairGenerator.getInstance("SM2", PROVIDER);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();
        Assertions.assertEquals(SM2_PUBKEY_LEN, pubKey.getEncoded().length);
        Assertions.assertEquals(SM2_PRIKEY_LEN, priKey.getEncoded().length);
    }

    @Test
    public void testKeyPairGenSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testKeyPairGen();
            return null;
        });
    }

    @Test
    public void testKeyPairParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testKeyPairGen();
            return null;
        });
    }

    @Test
    public void testPubKeyPointOnCurve() throws Exception {
        KeyPairGenerator keyPairGen
                = KeyPairGenerator.getInstance("SM2", PROVIDER);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPoint pubKeyPoint = pubKey.getW();
        boolean onCurve = checkPointOnCurve(pubKeyPoint);
        Assertions.assertTrue(onCurve);
    }

    private static boolean checkPointOnCurve(ECPoint pubKeyPoint) {
        BigInteger x = pubKeyPoint.getAffineX();
        BigInteger y = pubKeyPoint.getAffineY();
        EllipticCurve curve =  SM2ParameterSpec.instance().getCurve();
        ECFieldFp field = (ECFieldFp) curve.getField();
        BigInteger a = curve.getA();
        BigInteger b = curve.getB();
        BigInteger rhs = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(field.getP());
        BigInteger lhs = y.multiply(y).mod(field.getP());

        return lhs.equals(rhs);
    }
}
