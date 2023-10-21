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
import com.tencent.kona.sun.security.ec.ECOperator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.TestUtils.EMPTY;
import static com.tencent.kona.crypto.TestUtils.PROVIDER;

/**
 * The test for SM2 cipher.
 */
public class SM2CipherTest {

    private final static String PUB_KEY
            = "041D9E2952A06C913BAD21CCC358905ADB3A8097DB6F2F87EB5F393284EC2B7208C30B4D9834D0120216D6F1A73164FDA11A87B0A053F63D992BFB0E4FC1C5D9AD";
    private final static String PRI_KEY
            = "3B03B35C2F26DBC56F6D33677F1B28AF15E45FE9B594A6426BDCAD4A69FF976B";

    private final static byte[] MESSAGE = toBytes(
            "4003607F75BEEE81A027BB6D265BA1499E71D5D7CD8846396E119161A57E01EEB91BF8C9FE");

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testCipher() throws Exception {
        testCipher("SM2");
    }

    @Test
    public void testAlias() throws Exception {
        testCipher("OID.1.2.156.10197.1.301");
    }

    private void testCipher(String name) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec pubKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance(name, PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, priKey);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testCipherWithByteBuffer() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec pubKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        ByteBuffer ciphertext = ByteBuffer.allocate(150);
        cipher.doFinal(ByteBuffer.wrap(MESSAGE), ciphertext);
        ciphertext.flip();

        cipher.init(Cipher.DECRYPT_MODE, priKey);
        ByteBuffer cleartext = ByteBuffer.allocate(150);
        cipher.doFinal(ciphertext, cleartext);
        cleartext.flip();

        byte[] message = new byte[MESSAGE.length];
        cleartext.get(message);
        Assertions.assertArrayEquals(MESSAGE, message);
    }

    @Test
    public void testUpdate() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec pubKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        // No output on update operation
        cipher.update(MESSAGE, 0, MESSAGE.length / 2);
        cipher.update(MESSAGE, MESSAGE.length / 2,
                MESSAGE.length - MESSAGE.length / 2);
        // Output on final operation
        byte[] ciphertext = cipher.doFinal();

        cipher.init(Cipher.DECRYPT_MODE, priKey);
        // No output on update operation
        cipher.update(ciphertext, 0, ciphertext.length / 2);
        cipher.update(ciphertext, ciphertext.length / 2,
                ciphertext.length - ciphertext.length / 2);
        // Output on final operation
        byte[] cleartext = cipher.doFinal();

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testUpdateWithByteBuffer() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec pubKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        // No output on update operation
        cipher.update(ByteBuffer.wrap(MESSAGE), ByteBuffer.allocate(150));
        // Output on final operation
        ByteBuffer ciphertext = ByteBuffer.allocate(150);
        cipher.doFinal(ByteBuffer.allocate(0), ciphertext);
        ciphertext.flip();

        cipher.init(Cipher.DECRYPT_MODE, priKey);
        // No output on update operation
        cipher.update(ciphertext, ByteBuffer.allocate(150));
        // Output on final operation
        ByteBuffer cleartext = ByteBuffer.allocate(150);
        cipher.doFinal(ByteBuffer.allocate(0), cleartext);
        cleartext.flip();

        byte[] message = new byte[MESSAGE.length];
        cleartext.get(message);
        Assertions.assertArrayEquals(MESSAGE, message);
    }

    @Test
    public void testKeyRange() throws Exception {
        // privateKey = order - 2
        testKeyRange(2);

        // privateKey = order - 1
        testKeyRange(1);

        // privateKey = order
        Assertions.assertThrows(InvalidKeyException.class,
                () -> testKeyRange(0));

        // privateKey = order + 1
        Assertions.assertThrows(InvalidKeyException.class,
                () -> testKeyRange(-1));
    }

    private void testKeyRange(int orderOffset) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2");

        BigInteger privateKeyS = ECOperator.SM2.getOrder().subtract(
                BigInteger.valueOf(orderOffset));
        ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(
                new SM2PrivateKeySpec(privateKeyS.toByteArray()));

        ECPoint publicPoint = ECOperator.SM2.multiply(privateKeyS);
        ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(
                new SM2PublicKeySpec(publicPoint));

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testInvalidPubKey() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec pubKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, pubKey);

        byte[] ciphertext = cipher.doFinal(MESSAGE);
        // Replace C1 with an invalid public key, exactly zero
        for (int i = 5; i < 5 + 32; i++) {  // X bytes
            ciphertext[i] = 0;
        }
        for (int i = 40; i < 38 + 32; i++) { // Y bytes
            ciphertext[i] = 0;
        }

        cipher.init(Cipher.DECRYPT_MODE, priKey);
        Assertions.assertThrows(BadPaddingException.class,
                () -> cipher.doFinal(ciphertext));
    }

    @Test
    public void testTwice() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec pubKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        cipher.doFinal(MESSAGE);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, priKey);
        cipher.doFinal(ciphertext);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testCipher();
            return null;
        });
    }

    @Test
    public void testSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testCipher();
            return null;
        });
    }

    @Test
    public void testFailed() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec pubKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("SM2", PROVIDER);
        KeyPair altKeyPair = keyPairGenerator.generateKeyPair();

        cipher.init(Cipher.DECRYPT_MODE, altKeyPair.getPrivate());
        Assertions.assertThrows(
                BadPaddingException.class, () -> cipher.doFinal(ciphertext));
    }

    @Test
    public void testEmptyInput() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec pubKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] ciphertext = cipher.doFinal(EMPTY);

        cipher.init(Cipher.DECRYPT_MODE, priKey);
        Assertions.assertThrows(BadPaddingException.class,
                () -> cipher.doFinal(EMPTY));
        byte[] cleartext = cipher.doFinal(ciphertext);
        Assertions.assertArrayEquals(EMPTY, cleartext);
    }

    @Test
    public void testEmptyInputWithByteBuffer() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec pubKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        ByteBuffer ciphertextBuf = ByteBuffer.allocate(150);
        cipher.doFinal(ByteBuffer.allocate(0), ciphertextBuf);
        ciphertextBuf.flip();

        cipher.init(Cipher.DECRYPT_MODE, priKey);
        ByteBuffer cleartextBuf = ByteBuffer.allocate(150);
        Assertions.assertThrows(BadPaddingException.class,
                () -> cipher.doFinal(ByteBuffer.allocate(0), cleartextBuf));
        cipher.doFinal(ciphertextBuf, cleartextBuf);

        Assertions.assertEquals(0, cleartextBuf.position());
    }

    @Test
    public void testNullInput() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec pubKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> cipher.doFinal(null));

        cipher.init(Cipher.DECRYPT_MODE, priKey);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> cipher.doFinal(null));
    }

    @Test
    public void testNullInputWithByteBuffer() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec pubKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> cipher.doFinal(null, ByteBuffer.allocate(150)));

        cipher.init(Cipher.DECRYPT_MODE, priKey);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> cipher.doFinal(null, ByteBuffer.allocate(150)));
    }

    @Test
    public void testWithKeyGen() throws Exception {
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("SM2", PROVIDER);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testWithKeyGenParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testWithKeyGen();
            return null;
        });
    }

    @Test
    public void testCipherWithKeyGenSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testWithKeyGen();
            return null;
        });
    }
}
