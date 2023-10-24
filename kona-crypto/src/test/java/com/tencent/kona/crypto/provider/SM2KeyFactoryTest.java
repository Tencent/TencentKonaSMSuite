/*
 * Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
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
import com.tencent.kona.crypto.spec.SM2PrivateKeySpec;
import com.tencent.kona.crypto.spec.SM2PublicKeySpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.TestUtils.PROVIDER;

/**
 * The test for SM2KeyFactory.
 */
public class SM2KeyFactoryTest {

    // starts with 0x05
    private final static String INVALID_PUB_KEY
            = "051D9E2952A06C913BAD21CCC358905ADB3A8097DB6F2F87EB5F393284EC2B7208C30B4D9834D0120216D6F1A73164FDA11A87B0A053F63D992BFB0E4FC1C5D9AD";

    // 33-bytes
    private final static String INVALID_PRI_KEY
            = "3B03B35C2F26DBC56F6D33677F1B28AF15E45FE9B594A6426BDCAD4A69FF976B00";

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testGetKeySpecs() throws Exception {
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("SM2", PROVIDER);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);

        KeySpec pubKeySpec = keyFactory.getKeySpec(
                keyPair.getPublic(), SM2PublicKeySpec.class);
        Assertions.assertNotNull(pubKeySpec);

        KeySpec priKeySpec = keyFactory.getKeySpec(
                keyPair.getPrivate(), SM2PrivateKeySpec.class);
        Assertions.assertNotNull(priKeySpec);
    }

    @Test
    public void testGetKeySpecsFailed() throws Exception {
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("SM2", PROVIDER);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);

        Assertions.assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.getKeySpec(null, SM2PrivateKeySpec.class));

        Assertions.assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.getKeySpec(keyPair.getPublic(),
                        SM2PrivateKeySpec.class));

        Assertions.assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.getKeySpec(keyPair.getPrivate(),
                        SM2PublicKeySpec.class));

        Assertions.assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.getKeySpec(null, SM2PublicKeySpec.class));
    }

    @Test
    public void testGenerateKeys() throws Exception {
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("SM2", PROVIDER);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);

        KeySpec publicKeySpec = keyFactory.getKeySpec(
                publicKey, SM2PublicKeySpec.class);
        ECPublicKey ecPublicKey = (ECPublicKey) keyFactory.generatePublic(
                publicKeySpec);
        Assertions.assertArrayEquals(
                publicKey.getEncoded(), ecPublicKey.getEncoded());

        KeySpec privateKeySpec = keyFactory.getKeySpec(
                privateKey, SM2PrivateKeySpec.class);
        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyFactory.generatePrivate(
                privateKeySpec);
        Assertions.assertArrayEquals(
                privateKey.getEncoded(), ecPrivateKey.getEncoded());
    }

    @Test
    public void testGenerateKeysFailed() throws Exception {
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("SM2", PROVIDER);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);

        KeySpec publicKeySpec = keyFactory.getKeySpec(
                publicKey, SM2PublicKeySpec.class);
        Assertions.assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.generatePrivate(publicKeySpec));

        KeySpec privateKeySpec = keyFactory.getKeySpec(
                privateKey, SM2PrivateKeySpec.class);
        Assertions.assertThrows(InvalidKeySpecException.class,
                () -> keyFactory.generatePublic(privateKeySpec));

        Assertions.assertThrows(IllegalArgumentException.class,
                () -> keyFactory.generatePrivate(
                        new SM2PrivateKeySpec(toBytes(INVALID_PRI_KEY))));
        Assertions.assertThrows(NullPointerException.class,
                () -> keyFactory.generatePrivate(
                        new SM2PrivateKeySpec((byte[]) null)));

        Assertions.assertThrows(IllegalArgumentException.class,
                () -> keyFactory.generatePublic(
                        new SM2PublicKeySpec(toBytes(INVALID_PUB_KEY))));
        Assertions.assertThrows(NullPointerException.class,
                () -> keyFactory.generatePublic(
                        new SM2PublicKeySpec((byte[]) null)));
    }
}
