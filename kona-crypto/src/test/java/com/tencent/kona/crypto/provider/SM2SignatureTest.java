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
import com.tencent.kona.crypto.spec.SM2PrivateKeySpec;
import com.tencent.kona.crypto.spec.SM2PublicKeySpec;
import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;
import com.tencent.kona.crypto.util.Constants;
import com.tencent.kona.sun.security.ec.ECOperator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.TestUtils.EMPTY;
import static com.tencent.kona.crypto.TestUtils.PROVIDER;

/**
 * The test for SM2 signature.
 */
public class SM2SignatureTest {

    private final static String PUB_KEY
            = "041D9E2952A06C913BAD21CCC358905ADB3A8097DB6F2F87EB5F393284EC2B7208C30B4D9834D0120216D6F1A73164FDA11A87B0A053F63D992BFB0E4FC1C5D9AD";
    private final static String PRI_KEY
            = "3B03B35C2F26DBC56F6D33677F1B28AF15E45FE9B594A6426BDCAD4A69FF976B";
    private final static byte[] ID = toBytes("01234567");

    private final static byte[] MESSAGE = toBytes(
            "4003607F75BEEE81A027BB6D265BA1499E71D5D7CD8846396E119161A57E01EEB91BF8C9FE");

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testParameterSpec() throws Exception {
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("SM2", PROVIDER);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        SM2SignatureParameterSpec paramSpec
                = new SM2SignatureParameterSpec((ECPublicKey) keyPair.getPublic());
        Assertions.assertArrayEquals(Constants.defaultId(), paramSpec.getId());

        TestUtils.checkIAE(()-> new SM2SignatureParameterSpec(
                TestUtils.dataKB(8), (ECPublicKey) keyPair.getPublic()));
        TestUtils.checkNPE(()-> new SM2SignatureParameterSpec(
                TestUtils.dataKB(1), null));
    }

    @Test
    public void testSignature() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec publicKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        SM2SignatureParameterSpec paramSpec
                = new SM2SignatureParameterSpec(ID, (ECPublicKey) pubKey);

        Signature signer = Signature.getInstance("SM2", PROVIDER);
        signer.setParameter(paramSpec);
        signer.initSign(priKey);

        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SM2", PROVIDER);
        verifier.setParameter(paramSpec);
        verifier.initVerify(pubKey);
        verifier.update(MESSAGE);
        boolean verified = verifier.verify(signature);

        Assertions.assertTrue(verified);
    }

    @Test
    public void testSignatureWithByteBuffer() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec publicKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        SM2SignatureParameterSpec paramSpec
                = new SM2SignatureParameterSpec(ID, (ECPublicKey) pubKey);

        Signature signer = Signature.getInstance("SM2", PROVIDER);
        signer.setParameter(paramSpec);
        signer.initSign(priKey);

        signer.update(ByteBuffer.wrap(MESSAGE));
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SM2", PROVIDER);
        verifier.setParameter(paramSpec);
        verifier.initVerify(pubKey);
        verifier.update(ByteBuffer.wrap(MESSAGE));
        boolean verified = verifier.verify(signature);

        Assertions.assertTrue(verified);
    }

    @Test
    public void testKeyRange() throws Exception {
        // privateKey = order - 2
        testKeyRange(2);

        // privateKey = order - 1
        // Per the specification, the private key cannot be (order - 1)
        // on generating the signature.
        TestUtils.checkThrowable(InvalidKeyException.class, () -> testKeyRange(1));

        // privateKey = order
        TestUtils.checkThrowable(InvalidKeyException.class, () -> testKeyRange(0));

        // privateKey = order + 1
        TestUtils.checkThrowable(InvalidKeyException.class, () -> testKeyRange(-1));
    }

    // orderOffset: the relative offset to the order
    private void testKeyRange(int orderOffset) throws Exception {
        BigInteger privateKeyS = ECOperator.SM2.getOrder().subtract(
                BigInteger.valueOf(orderOffset));
        ECPrivateKey privateKey = new SM2PrivateKey(privateKeyS);

        ECPoint publicPoint = ECOperator.SM2.multiply(privateKeyS);
        ECPublicKey publicKey = new SM2PublicKey(publicPoint);

        Signature signer = Signature.getInstance("SM2", PROVIDER);
        signer.initSign(privateKey);
        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SM2", PROVIDER);
        verifier.initVerify(publicKey);
        verifier.update(MESSAGE);
        boolean verified = verifier.verify(signature);

        Assertions.assertTrue(verified);
    }

    @Test
    public void testEmptyInput() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec publicKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        SM2SignatureParameterSpec paramSpec
                = new SM2SignatureParameterSpec(ID, (ECPublicKey) pubKey);

        Signature signer = Signature.getInstance("SM2", PROVIDER);
        signer.setParameter(paramSpec);
        signer.initSign(priKey);

        signer.update(EMPTY);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SM2", PROVIDER);
        verifier.setParameter(paramSpec);
        verifier.initVerify(pubKey);
        verifier.update(EMPTY);
        boolean verified = verifier.verify(signature);

        Assertions.assertTrue(verified);
    }

    @Test
    public void testEmptyInputWithByteBuffer() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec publicKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        SM2SignatureParameterSpec paramSpec
                = new SM2SignatureParameterSpec(ID, (ECPublicKey) pubKey);

        Signature signer = Signature.getInstance("SM2", PROVIDER);
        signer.setParameter(paramSpec);
        signer.initSign(priKey);

        signer.update(ByteBuffer.allocate(0));
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SM2", PROVIDER);
        verifier.setParameter(paramSpec);
        verifier.initVerify(pubKey);
        verifier.update(ByteBuffer.allocate(0));
        boolean verified = verifier.verify(signature);

        Assertions.assertTrue(verified);
    }

    @Test
    public void testNullInput() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec publicKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        SM2SignatureParameterSpec paramSpec
                = new SM2SignatureParameterSpec(ID, (ECPublicKey) pubKey);

        Signature signer = Signature.getInstance("SM2", PROVIDER);
        signer.setParameter(paramSpec);
        signer.initSign(priKey);
        Assertions.assertThrows(NullPointerException.class,
                () -> signer.update((byte[]) null));

        Signature verifier = Signature.getInstance("SM2", PROVIDER);
        verifier.setParameter(paramSpec);
        verifier.initVerify(pubKey);
        Assertions.assertThrows(NullPointerException.class,
                () -> signer.update((byte[]) null));
    }

    @Test
    public void testNullInputWithByteBuffer() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec publicKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        SM2SignatureParameterSpec paramSpec
                = new SM2SignatureParameterSpec(ID, (ECPublicKey) pubKey);

        Signature signer = Signature.getInstance("SM2", PROVIDER);
        signer.setParameter(paramSpec);
        signer.initSign(priKey);
        Assertions.assertThrows(NullPointerException.class,
                () -> signer.update((ByteBuffer) null));

        Signature verifier = Signature.getInstance("SM2", PROVIDER);
        verifier.setParameter(paramSpec);
        verifier.initVerify(pubKey);
        Assertions.assertThrows(NullPointerException.class,
                () -> signer.update((ByteBuffer) null));
    }

    @Test
    public void testWithoutParamSpec() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec publicKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        Signature signer = Signature.getInstance("SM2", PROVIDER);
        signer.initSign(priKey);

        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SM2", PROVIDER);
        verifier.initVerify(pubKey);
        verifier.update(MESSAGE);
        boolean verified = verifier.verify(signature);

        Assertions.assertTrue(verified);
    }

    @Test
    public void testTwice() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec publicKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        SM2SignatureParameterSpec paramSpec
                = new SM2SignatureParameterSpec(ID, (ECPublicKey) pubKey);

        Signature signer = Signature.getInstance("SM2", PROVIDER);
        signer.setParameter(paramSpec);
        signer.initSign(priKey);

        signer.update(MESSAGE, 0, MESSAGE.length / 2);
        signer.update(MESSAGE, MESSAGE.length / 2,
                MESSAGE.length - MESSAGE.length / 2);
        byte[] signature = signer.sign();

        signer.update(MESSAGE);
        signature = signer.sign();

        Signature verifier = Signature.getInstance("SM2", PROVIDER);
        verifier.setParameter(paramSpec);
        verifier.initVerify(pubKey);

        verifier.update(MESSAGE);
        Assertions.assertTrue(verifier.verify(signature));

        verifier.update(MESSAGE, 0, MESSAGE.length / 2);
        verifier.update(MESSAGE, MESSAGE.length / 2,
                MESSAGE.length - MESSAGE.length / 2);
        Assertions.assertTrue(verifier.verify(signature));
    }

    @Test
    public void testParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testSignature();
            return null;
        });
    }

    @Test
    public void testSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testSignature();
            return null;
        });
    }

    @Test
    public void testWithKeyGen() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SM2");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        SM2SignatureParameterSpec paramSpec
                = new SM2SignatureParameterSpec(
                ID, (ECPublicKey) keyPair.getPublic());

        Signature signer = Signature.getInstance("SM2", PROVIDER);
        signer.setParameter(paramSpec);
        signer.initSign(keyPair.getPrivate());

        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SM2", PROVIDER);
        verifier.setParameter(paramSpec);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(MESSAGE);
        boolean verified = verifier.verify(signature);

        Assertions.assertTrue(verified);
    }

    @Test
    public void testWithKeyGenParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testWithKeyGen();
            return null;
        });
    }

    @Test
    public void testSignatureWithKeyGenSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testWithKeyGen();
            return null;
        });
    }
}
