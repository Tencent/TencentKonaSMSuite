/*
 * Copyright (C) 2022, 2024, THL A29 Limited, a Tencent company. All rights reserved.
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

package com.tencent.kona.pkix.provider;

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.sun.security.x509.X509Key;
import com.tencent.kona.pkix.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * The test for KeyFactory.
 */
public class KeyFactoryTest {

    private static final String PASSPHRASE = "password";

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testGetKeySpecs() throws Exception {
        X509Certificate x509Cert = TestUtils.certAsFile("ca-sm2sm2.crt");
        PublicKey publicKey = x509Cert.getPublicKey();

        KeyFactory keyFactory = KeyFactory.getInstance("EC", CryptoInsts.PROV);

        ECPublicKeySpec publicKeySpec = keyFactory.getKeySpec(
                publicKey, ECPublicKeySpec.class);
        Assertions.assertNotNull(publicKeySpec);

        X509EncodedKeySpec x509KeySpec = keyFactory.getKeySpec(
                publicKey, X509EncodedKeySpec.class);
        Assertions.assertNotNull(x509KeySpec);

        PrivateKey privateKey = TestUtils.ecPrivateKeyAsFile("ca-sm2sm2.key");

        ECPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(
                privateKey, ECPrivateKeySpec.class);
        Assertions.assertNotNull(privateKeySpec);

        PKCS8EncodedKeySpec pkcs8KeySpec = keyFactory.getKeySpec(
                privateKey, PKCS8EncodedKeySpec.class);
        Assertions.assertNotNull(pkcs8KeySpec);
    }

    @Test
    public void testGeneratePublicKey() throws Exception {
        X509Certificate x509Cert = TestUtils.certAsFile("ca-sm2sm2.crt");
        ECPublicKey publicKey = (ECPublicKey) x509Cert.getPublicKey();

        KeyFactory keyFactory = KeyFactory.getInstance("EC", CryptoInsts.PROV);

        ECPublicKeySpec ecPublicKeySpec = keyFactory.getKeySpec(
                publicKey, ECPublicKeySpec.class);
        ECPublicKey ecPublicKey = (ECPublicKey) keyFactory.generatePublic(
                ecPublicKeySpec);
        Assertions.assertEquals(publicKey.getW(), ecPublicKey.getW());

        X509EncodedKeySpec x509KeySpec = keyFactory.getKeySpec(
                publicKey, X509EncodedKeySpec.class);
        X509Key x509Key = (X509Key) keyFactory.generatePublic(x509KeySpec);
        Assertions.assertArrayEquals(
                publicKey.getEncoded(), x509Key.getEncoded());
    }

    @Test
    public void testGeneratePrivateKey() throws Exception {
        testGeneratePrivateKey(TestUtils.rsaPrivateKeyAsFile("ca-rsarsa.key"));
        testGeneratePrivateKey(TestUtils.ecPrivateKeyAsFile("ca-p256ecdsa.key"));
        testGeneratePrivateKey(TestUtils.ecPrivateKeyAsFile("ca-p256sm2.key"));
        testGeneratePrivateKey(TestUtils.ecPrivateKeyAsFile("ca-sm2ecdsa.key"));
        testGeneratePrivateKey(TestUtils.ecPrivateKeyAsFile("ca-sm2sm2.key"));
    }

    @Test
    public void testGeneratePrivateKeyWithEncryptedKey() throws Exception {
        testGeneratePrivateKey(TestUtils.encryptedRSAPrivateKeyAsFile(
                "ca-rsarsa_enc.key", PASSPHRASE));
        testGeneratePrivateKey(TestUtils.encryptedECPrivateKeyAsFile(
                "ca-p256ecdsa_enc.key", PASSPHRASE));
        testGeneratePrivateKey(TestUtils.encryptedECPrivateKeyAsFile(
                "ca-p256sm2_enc.key", PASSPHRASE));
        testGeneratePrivateKey(TestUtils.encryptedECPrivateKeyAsFile(
                "ca-sm2ecdsa_enc.key", PASSPHRASE));
        testGeneratePrivateKey(TestUtils.encryptedECPrivateKeyAsFile(
                "ca-sm2sm2_enc.key", PASSPHRASE));
        testGeneratePrivateKey(TestUtils.encryptedECPrivateKeyAsFile(
                "ca-sm2sm2_enc-sm4.key", PASSPHRASE));
    }

    private void testGeneratePrivateKey(PrivateKey privateKey)
            throws Exception {
        if (privateKey instanceof RSAPrivateKey) {
            testGenerateRSAPrivateKey((RSAPrivateKey) privateKey);
        } else if (privateKey instanceof ECPrivateKey) {
            testGenerateECPrivateKey((ECPrivateKey) privateKey);
        }
    }

    private void testGenerateRSAPrivateKey(RSAPrivateKey privateKey)
            throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        RSAPrivateKeySpec rsaPrivateKeySpec = keyFactory.getKeySpec(
                privateKey, RSAPrivateKeySpec.class);
        RSAPrivateKey ecPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(
                rsaPrivateKeySpec);
        Assertions.assertEquals(
                privateKey.getPrivateExponent(),
                ecPrivateKey.getPrivateExponent());

        PKCS8EncodedKeySpec pkcs8KeySpec = keyFactory.getKeySpec(
                privateKey, PKCS8EncodedKeySpec.class);
        RSAPrivateKey pkcs8Key = (RSAPrivateKey) keyFactory.generatePrivate(
                pkcs8KeySpec);
        Assertions.assertArrayEquals(
                privateKey.getEncoded(), pkcs8Key.getEncoded());
    }

    private void testGenerateECPrivateKey(ECPrivateKey privateKey)
            throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("EC", CryptoInsts.PROV);

        ECPrivateKeySpec ecPrivateKeySpec = keyFactory.getKeySpec(
                privateKey, ECPrivateKeySpec.class);
        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyFactory.generatePrivate(
                ecPrivateKeySpec);
        Assertions.assertEquals(privateKey.getS(), ecPrivateKey.getS());

        PKCS8EncodedKeySpec pkcs8KeySpec = keyFactory.getKeySpec(
                privateKey, PKCS8EncodedKeySpec.class);
        ECPrivateKey pkcs8Key = (ECPrivateKey) keyFactory.generatePrivate(
                pkcs8KeySpec);
        Assertions.assertArrayEquals(
                privateKey.getEncoded(), pkcs8Key.getEncoded());
    }
}
