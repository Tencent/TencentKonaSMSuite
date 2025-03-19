/*
 * Copyright (C) 2025, THL A29 Limited, a Tencent company. All rights reserved.
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
import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;
import com.tencent.kona.sun.security.ec.ECOperator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The test for EC key pair generation on common curves.
 */
public class KonaECKeyPairGeneratorTest {

    private final static byte[] MESSAGE = "MESSAGE".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testKeyPairGenWithName() throws Exception {
        testKeyPairGen("secp256r1", ECOperator.SECP256R1);
        testKeyPairGen("secp384r1", ECOperator.SECP384R1);
        testKeyPairGen("secp521r1", ECOperator.SECP521R1);
        testKeyPairGen("curvesm2", ECOperator.SM2);
    }

    private void testKeyPairGen(String curve, ECOperator ecOperator)
            throws Exception {
        KeyPair keyPair = keyPair(curve);
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();

        ECPoint pubPoint = ecOperator.multiply(
                ecOperator.getGenerator(), priKey.getS());
        assertEquals(pubKey.getW(), pubPoint);
    }

    @Test
    public void testSignatureWithECKeyPair() throws Exception {
        testSignatureWithECKeyPair("secp256r1");
        testSignatureWithECKeyPair("secp384r1");
        testSignatureWithECKeyPair("secp521r1");
        testSignatureWithECKeyPair("curvesm2");
    }

    private void testSignatureWithECKeyPair(String curve) throws Exception {
        KeyPair keyPair = keyPair(curve);
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();

        Signature signer = Signature.getInstance("SHA256withECDSA", PROVIDER);
        signer.initSign(priKey);
        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withECDSA", PROVIDER);
        verifier.initVerify(pubKey);
        verifier.update(MESSAGE);
        boolean verified = verifier.verify(signature);

        assertTrue(verified);
    }

    private static KeyPair keyPair(String curve) throws Exception {
        KeyPairGenerator keyPairGen
                = KeyPairGenerator.getInstance("EC", PROVIDER);
        keyPairGen.initialize(new ECGenParameterSpec(curve));
        return keyPairGen.generateKeyPair();
    }
}
