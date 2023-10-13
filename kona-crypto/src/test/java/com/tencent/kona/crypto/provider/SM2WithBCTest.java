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
import com.tencent.kona.crypto.spec.SM2KeyAgreementParamSpec;
import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;
import com.tencent.kona.crypto.util.Constants;
import com.tencent.kona.crypto.util.SM2Ciphertext;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.crypto.agreement.SM2KeyExchange;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.SM2KeyExchangePrivateParameters;
import org.bouncycastle.crypto.params.SM2KeyExchangePublicParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static com.tencent.kona.crypto.spec.SM2ParameterSpec.COFACTOR;
import static com.tencent.kona.crypto.spec.SM2ParameterSpec.CURVE;
import static com.tencent.kona.crypto.spec.SM2ParameterSpec.GENERATOR;
import static com.tencent.kona.crypto.spec.SM2ParameterSpec.ORDER;

/**
 * The test for SM2 with BouncyCastle.
 */
public class SM2WithBCTest {

    private final static byte[] MESSAGE = TestUtils.data(1);

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testKonaCipherWithBCKeyPair() throws Exception {
        testCipher(keyPairBC());
    }

    @Test
    public void testBCCipherWithKonaKeyPair() throws Exception {
        testCipher(keyPair());
    }

    private void testCipher(KeyPair keyPair)
            throws Exception {
        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        // Ciphertext produced by Kona
        // The format is C1||C3||C2 ASN.1 DER
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        Cipher cipherBC = Cipher.getInstance("SM2", "BC");
        cipherBC.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        // Ciphertext produced by BC
        // The format is C1||C2||C3
        byte[] ciphertextBC = cipherBC.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        // Convert BC ciphertext to Kona ciphertext
        byte[] derC1C3C2 = SM2Ciphertext.builder()
                .format(SM2Ciphertext.Format.RAW_C1C2C3)
                .encodedCiphertext(ciphertextBC)
                .build()
                .derC1C3C2();
        byte[] cleartext = cipher.doFinal(derC1C3C2);
        Assertions.assertArrayEquals(MESSAGE, cleartext);

        cipherBC.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        // Convert Kona ciphertext to BC ciphertext
        byte[] rawC1C2C3 = SM2Ciphertext.builder()
                .format(SM2Ciphertext.Format.DER_C1C3C2)
                .encodedCiphertext(ciphertext)
                .build()
                .rawC1C2C3();
        byte[] cleartextBC = cipherBC.doFinal(rawC1C2C3);
        Assertions.assertArrayEquals(MESSAGE, cleartextBC);
    }

    @Test
    public void testKonaSignatureWithBCKeyPair() throws Exception {
        testSignature(keyPairBC());
    }

    @Test
    public void testBCSignatureWithKonaKeyPair() throws Exception {
        testSignature(keyPair());
    }

    private void testSignature(KeyPair keyPair) throws Exception {
        Signature signature = Signature.getInstance("SM2", PROVIDER);
        SM2SignatureParameterSpec paramSpec = new SM2SignatureParameterSpec(
                Constants.defaultId(),
                (ECPublicKey) keyPair.getPublic());
        signature.setParameter(paramSpec);
        signature.initSign(keyPair.getPrivate());
        signature.update(MESSAGE);
        // Signature produced by Kona
        byte[] sign = signature.sign();

        Signature signatureBC = Signature.getInstance(
                GMObjectIdentifiers.sm2sign_with_sm3.toString(), "BC");
        SM2ParameterSpec paramSpecBC = new SM2ParameterSpec(
                Constants.defaultId());
        signatureBC.setParameter(paramSpecBC);
        signatureBC.initSign(keyPair.getPrivate());
        signatureBC.update(MESSAGE);
        // Signature produced by BC
        byte[] signBC = signatureBC.sign();

        signature = Signature.getInstance("SM2", PROVIDER);
        signature.setParameter(paramSpec);
        signature.initVerify(keyPair.getPublic());
        signature.update(MESSAGE);
        // Kona verifies the signature produced by BC
        Assertions.assertTrue(signature.verify(signBC));

        signatureBC.setParameter(paramSpecBC);
        signatureBC.initVerify(keyPair.getPublic());
        signatureBC.update(MESSAGE);
        // BC verifies the signature produced by Kona
        Assertions.assertTrue(signatureBC.verify(sign));
    }

    @Test
    public void testKeyAgreement() throws Exception {
        testKeyAgreement(true);
        testKeyAgreement(false);
    }

    private void testKeyAgreement(boolean konaIsInitiator) throws Exception {
        byte[] idA = "User A".getBytes(StandardCharsets.UTF_8);
        byte[] idB = "B Part".getBytes(StandardCharsets.UTF_8);

        KeyPair keyPairA = keyPair();
        ECPrivateKey ecPrivateKeyA = (ECPrivateKey) keyPairA.getPrivate();
        ECPublicKey ecPublicKeyA = (ECPublicKey) keyPairA.getPublic();

        KeyPair tmpkeyPairA = keyPair();
        ECPrivateKey tmpECPrivateKeyA = (ECPrivateKey) tmpkeyPairA.getPrivate();
        ECPublicKey tmpECPublicKeyA = (ECPublicKey) tmpkeyPairA.getPublic();

        KeyPair keyPairB = keyPair();
        ECPrivateKey ecPrivateKeyB = (ECPrivateKey) keyPairB.getPrivate();
        ECPublicKey ecPublicKeyB = (ECPublicKey) keyPairB.getPublic();

        KeyPair tmpkeyPairB = keyPair();
        ECPrivateKey tmpECPrivateKeyB = (ECPrivateKey) tmpkeyPairB.getPrivate();
        ECPublicKey tmpECPublicKeyB = (ECPublicKey) tmpkeyPairB.getPublic();

        SM2KeyAgreementParamSpec paramSpec = new SM2KeyAgreementParamSpec(
                idA, ecPrivateKeyA, ecPublicKeyA,
                idB, ecPublicKeyB,
                konaIsInitiator, 16);
        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2", PROVIDER);
        keyAgreement.init(tmpECPrivateKeyA, paramSpec);
        keyAgreement.doPhase(tmpECPublicKeyB, true);
        byte[] sharedKey = keyAgreement.generateSecret();

        ECCurve ecCurve = new ECCurve.Fp(
                ((ECFieldFp) CURVE.getField()).getP(),
                CURVE.getA(), CURVE.getB(), ORDER, COFACTOR);
        ECPoint genPoint = ecCurve.createPoint(
                GENERATOR.getAffineX(), GENERATOR.getAffineY());
        ECDomainParameters ecDomainParams = new ECDomainParameters(
                ecCurve, genPoint, ORDER);

        ECPrivateKeyParameters privateKeyParamsB = new ECPrivateKeyParameters(
                ecPrivateKeyB.getS(), ecDomainParams);
        ECPrivateKeyParameters tmpPrivateKeyParamsB = new ECPrivateKeyParameters(
                tmpECPrivateKeyB.getS(), ecDomainParams);
        ECPublicKeyParameters publicKeyParamsA = new ECPublicKeyParameters(
                EC5Util.convertPoint(ecCurve, ecPublicKeyA.getW()),
                ecDomainParams);
        ECPublicKeyParameters tmpPublicKeyParamsA = new ECPublicKeyParameters(
                EC5Util.convertPoint(ecCurve, tmpECPublicKeyA.getW()),
                ecDomainParams);
        SM2KeyExchange keyAgreementBC = new SM2KeyExchange();
        keyAgreementBC.init(new ParametersWithID(
                new SM2KeyExchangePrivateParameters(
                        !konaIsInitiator, privateKeyParamsB, tmpPrivateKeyParamsB),
                idB));
        byte[] sharedKeyBC = keyAgreementBC.calculateKey(128,
                new ParametersWithID(new SM2KeyExchangePublicParameters(
                        publicKeyParamsA, tmpPublicKeyParamsA), idA));

        Assertions.assertArrayEquals(sharedKey, sharedKeyBC);
    }

    private KeyPair toBCKeyPair(KeyPair keyPair) {
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();

        BCECPublicKey pubKeyBC = new BCECPublicKey(pubKey, null);
        BCECPrivateKey priKeyBC = new BCECPrivateKey(priKey, null);
        return new KeyPair(pubKeyBC, priKeyBC);
    }

    private KeyPair keyPair() throws Exception {
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("SM2", PROVIDER);
        return keyPairGenerator.generateKeyPair();
    }

    private KeyPair keyPairBC() throws Exception {
        ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGen.initialize(sm2Spec);
        return keyPairGen.generateKeyPair();
    }
}
