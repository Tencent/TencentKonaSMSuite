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
import com.tencent.kona.sun.security.ec.ECOperator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;

/**
 * The test for EC key pair generation on SM2 curve.
 */
public class ECKeyPairGeneratorTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testKeyPairGenWithParams() throws Exception {
        testKeyPairGen(SM2ParameterSpec.instance());
    }

    @Test
    public void testKeyPairGenWithName() throws Exception {
        testKeyPairGen(new ECGenParameterSpec("curveSM2"));
    }

    private void testKeyPairGen(AlgorithmParameterSpec spec) throws Exception {
        KeyPairGenerator keyPairGen
                = KeyPairGenerator.getInstance("EC", PROVIDER);
        keyPairGen.initialize(spec);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();

        ECPoint pubPoint = ECOperator.SM2.multiply(
                ECOperator.SM2.getGenerator(), priKey.getS());
        Assertions.assertEquals(pubKey.getW(), pubPoint);
    }

    @Test
    public void testKeyPairGenKeySize() throws Exception {
        KeyPairGenerator keyPairGen
                = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256); // should select secp256r1 rather than curveSM2
        KeyPair keyPair = keyPairGen.generateKeyPair();
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();

        ECPoint pubPoint = ECOperator.SECP256R1.multiply(
                ECOperator.SECP256R1.getGenerator(), priKey.getS());
        Assertions.assertEquals(pubKey.getW(), pubPoint);
    }
}
