/*
 * Copyright (C) 2022, 2025, Tencent. All rights reserved.
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

import com.tencent.kona.crypto.KonaCryptoNativeOneShotProvider;
import com.tencent.kona.crypto.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.AlgorithmParameterSpec;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static com.tencent.kona.crypto.util.Constants.SM4_GCM_IV_LEN;
import static com.tencent.kona.crypto.util.Constants.SM4_GCM_TAG_LEN;

/**
 * The test for SM4 cipher.
 */
public class SM4Test {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] IV = toBytes("00000000000000000000000000000001");
    private static final byte[] GCM_IV = toBytes("000000000000000000000001");
    private static final byte[] ALT_GCM_IV = toBytes("000000000000000000000002");
    private static final byte[] AAD = toBytes("616263");

    private static final byte[] MESSAGE = toBytes(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testSpec() throws Exception {
        byte[] key = toBytes("0123456789abcdef0123456789abcdef");

        SecretKey secretKey = new SecretKeySpec(key, "SM4");
        Assertions.assertArrayEquals(key, secretKey.getEncoded());

        Cipher.getInstance("SM4/CBC/NoPadding", PROVIDER);
        Cipher.getInstance("SM4/CBC/PKCS7Padding", PROVIDER);
        Cipher.getInstance("SM4/CTR/NoPadding", PROVIDER);
        Cipher.getInstance("SM4/ECB/NoPadding", PROVIDER);
        Cipher.getInstance("SM4/ECB/PKCS7Padding", PROVIDER);
        Cipher.getInstance("SM4/GCM/NoPadding", PROVIDER);
    }

    @Test
    public void testIvLength() throws Exception {
        byte[] iv_12 = toBytes("000102030405060708090A0B");
        byte[] iv_16 = toBytes("000102030405060708090A0B0C0D0E0F");
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");

        Cipher cipherCBC = Cipher.getInstance("SM4/CBC/PKCS7Padding", PROVIDER);
        cipherCBC.init(Cipher.ENCRYPT_MODE, secretKey,
                new IvParameterSpec(iv_16));
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> cipherCBC.init(Cipher.ENCRYPT_MODE, secretKey,
                        new IvParameterSpec(iv_12)));

        Cipher cipherGCM = Cipher.getInstance("SM4/GCM/NoPadding", PROVIDER);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> cipherGCM.init(Cipher.ENCRYPT_MODE, secretKey,
                        new IvParameterSpec(iv_16)));
        cipherGCM.init(Cipher.ENCRYPT_MODE, secretKey,
                new GCMParameterSpec(SM4_GCM_TAG_LEN * 8, iv_12));
    }

    @Test
    public void testKAT() throws Exception {
        byte[] message = toBytes("0123456789abcdeffedcba9876543210");
        byte[] key = toBytes("0123456789abcdeffedcba9876543210");
        byte[] expectedCiphertext = toBytes("681edf34d206965e86b3e94f536e4246");

        SecretKey secretKey = new SecretKeySpec(key, "SM4");
        Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ciphertext = cipher.doFinal(message);
        Assertions.assertArrayEquals(expectedCiphertext, ciphertext);

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] cleartext = cipher.doFinal(ciphertext);
        Assertions.assertArrayEquals(message, cleartext);

        // Without SM4 key factory
        secretKey = new SecretKeySpec(key, "SM4");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        ciphertext = cipher.doFinal(message);
        Assertions.assertArrayEquals(expectedCiphertext, ciphertext);

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        cleartext = cipher.doFinal(ciphertext);
        Assertions.assertArrayEquals(message, cleartext);
    }

    @Test
    public void testKATWithByteBuffer() throws Exception {
        byte[] message = toBytes("0123456789abcdeffedcba9876543210");
        byte[] key = toBytes("0123456789abcdeffedcba9876543210");
        byte[] expectedCiphertext = toBytes("681edf34d206965e86b3e94f536e4246");

        SecretKey secretKey = new SecretKeySpec(key, "SM4");
        Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        ByteBuffer plaintext = ByteBuffer.wrap(message);
        ByteBuffer ciphertext = ByteBuffer.allocate(message.length);

        cipher.doFinal(plaintext, ciphertext);
        Assertions.assertArrayEquals(expectedCiphertext, ciphertext.array());

        plaintext.flip();
        ciphertext.flip();
        ByteBuffer cleartext = ByteBuffer.allocate(message.length);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        cipher.doFinal(ciphertext, cleartext);
        Assertions.assertArrayEquals(message, cleartext.array());

        // Without SM4 key factory
        secretKey = new SecretKeySpec(key, "SM4");

        plaintext.flip();
        ciphertext.flip();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        cipher.doFinal(plaintext, ciphertext);
        Assertions.assertArrayEquals(expectedCiphertext, ciphertext.array());

        ciphertext.flip();
        cleartext.flip();
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        cipher.doFinal(ciphertext, cleartext);
        Assertions.assertArrayEquals(message, cleartext.array());
    }

    @Test
    public void testEmpty() throws Exception {
        byte[] key = toBytes("0123456789abcdeffedcba9876543210");

        SecretKeySpec keySpec = new SecretKeySpec(key, "SM4");

        Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] ciphertext = cipher.doFinal(TestUtils.EMPTY);
        Assertions.assertArrayEquals(TestUtils.EMPTY, ciphertext);

        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] cleartext = cipher.doFinal(ciphertext);
        Assertions.assertArrayEquals(TestUtils.EMPTY, cleartext);
    }

    @Test
    public void testEmptyWithByteBuffer() throws Exception {
        byte[] key = toBytes("0123456789abcdeffedcba9876543210");

        SecretKeySpec keySpec = new SecretKeySpec(key, "SM4");

        ByteBuffer plaintext = ByteBuffer.allocate(0);
        ByteBuffer ciphertext = ByteBuffer.allocate(64);
        Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        cipher.doFinal(plaintext, ciphertext);
        Assertions.assertEquals(0, ciphertext.position());

        ciphertext.flip();
        ByteBuffer cleartext = ByteBuffer.allocate(64);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        cipher.doFinal(plaintext, cleartext);
        Assertions.assertEquals(0, cleartext.position());
    }

    @Test
    public void testNull() throws Exception {
        byte[] key = toBytes("0123456789abcdeffedcba9876543210");

        SecretKeySpec keySpec = new SecretKeySpec(key, "SM4");

        Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> cipher.doFinal(null));

        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> cipher.doFinal(null));
    }

    @Test
    public void testNoSpace() throws Exception {
        byte[] key = toBytes("0123456789abcdeffedcba9876543210");

        SecretKeySpec keySpec = new SecretKeySpec(key, "SM4");

        ByteBuffer plaintext = ByteBuffer.wrap(MESSAGE);

        Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        Assertions.assertThrows(
                ShortBufferException.class,
                () -> cipher.doFinal(plaintext, ByteBuffer.allocate(MESSAGE.length - 1)));

        ByteBuffer ciphertext = ByteBuffer.allocate(MESSAGE.length);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        Assertions.assertThrows(
                ShortBufferException.class,
                () -> cipher.doFinal(ciphertext, ByteBuffer.allocate(MESSAGE.length - 1)));
    }

    @Test
    public void testNullWithByteBuffer() throws Exception {
        byte[] key = toBytes("0123456789abcdeffedcba9876543210");

        SecretKeySpec keySpec = new SecretKeySpec(key, "SM4");

        Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> cipher.doFinal(null, null));

        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> cipher.doFinal(null, null));
    }

    @Test
    public void testCBCModeWithPadding() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec paramSpec = new IvParameterSpec(IV);
        Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testCBCModeWithPaddingParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testCBCModeWithPadding();
            return null;
        });
    }

    @Test
    public void testCBCModeWithPaddingSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testCBCModeWithPadding();
            return null;
        });
    }

    @Test
    public void testCBCModeWithoutPadding() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec paramSpec = new IvParameterSpec(IV);
        Cipher cipher = Cipher.getInstance("SM4/CBC/NoPadding", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testCBCModeWithoutPaddingParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testCBCModeWithoutPadding();
            return null;
        });
    }

    @Test
    public void testCBCModeWithoutPaddingSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testCBCModeWithoutPadding();
            return null;
        });
    }

    @Test
    public void testCTRMode() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec paramSpec = new IvParameterSpec(IV);
        Cipher cipher = Cipher.getInstance("SM4/CTR/NoPadding", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testCTRModeParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testCTRMode();
            return null;
        });
    }

    @Test
    public void testCTRModeSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testCTRMode();
            return null;
        });
    }

    @Test
    public void testECBModeWithPadding() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS7Padding", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testECBModeWithPaddingParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testECBModeWithPadding();
            return null;
        });
    }

    @Test
    public void testECBModeWithPaddingSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testECBModeWithPadding();
            return null;
        });
    }

    @Test
    public void testECBModeWithoutPadding() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testECBModeWithoutPaddingParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testECBModeWithoutPadding();
            return null;
        });
    }

    @Test
    public void testECBModeWithoutPaddingSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testECBModeWithoutPadding();
            return null;
        });
    }

    @Test
    public void testGCMMode() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        GCMParameterSpec paramSpec = new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, GCM_IV);
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testGCMModeWithByteBuffer() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        GCMParameterSpec paramSpec = new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, GCM_IV);
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);

        ByteBuffer messageBuf = ByteBuffer.allocate(MESSAGE.length);
        messageBuf.put(MESSAGE);
        messageBuf.flip();
        ByteBuffer ciphertextBuf = ByteBuffer.allocate(128);
        cipher.doFinal(messageBuf, ciphertextBuf);
        ciphertextBuf.flip();

        ByteBuffer cleartextBuf = ByteBuffer.allocate(MESSAGE.length);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        cipher.doFinal(ciphertextBuf, cleartextBuf);

        Assertions.assertArrayEquals(MESSAGE, cleartextBuf.array());
    }

    @Test
    public void testGCMModeWithReadonlyByteBuffer() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        GCMParameterSpec paramSpec = new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, GCM_IV);
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);

        ByteBuffer messageBuf = ByteBuffer.allocate(MESSAGE.length);
        messageBuf.put(MESSAGE);
        messageBuf.flip();
        messageBuf = messageBuf.asReadOnlyBuffer();
        ByteBuffer ciphertextBuf = ByteBuffer.allocate(128);
        cipher.doFinal(messageBuf, ciphertextBuf);
        ciphertextBuf.flip();
        ciphertextBuf = ciphertextBuf.asReadOnlyBuffer();

        ByteBuffer cleartextBuf = ByteBuffer.allocate(MESSAGE.length);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        cipher.doFinal(ciphertextBuf, cleartextBuf);

        Assertions.assertArrayEquals(MESSAGE, cleartextBuf.array());
    }

    @Test
    public void testGCMModeWithSameByteBuffer() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        GCMParameterSpec paramSpec = new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, GCM_IV);
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);

        ByteBuffer encryptBuf = ByteBuffer.allocate(512);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> cipher.doFinal(encryptBuf, encryptBuf));

        ByteBuffer decryptBuf = ByteBuffer.allocate(MESSAGE.length);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> cipher.doFinal(decryptBuf, decryptBuf));
    }

    @Test
    public void testGCMModeWithSameByteArray() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        GCMParameterSpec paramSpec = new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, GCM_IV);
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);

        byte[] hbArray = new byte[512];

        ByteBuffer messageBuf = ByteBuffer.wrap(hbArray);
        messageBuf.put(MESSAGE);
        int messageLength = messageBuf.position();
        messageBuf.flip();

        ByteBuffer ciphertextBuf = ByteBuffer.wrap(hbArray);
        ciphertextBuf.position(messageLength);
        cipher.doFinal(messageBuf, ciphertextBuf);
        int ciphertextLength = ciphertextBuf.position() - messageLength;
        ciphertextBuf.limit(ciphertextBuf.position());
        ciphertextBuf.position(messageLength);

        ByteBuffer cleartextBuf = ByteBuffer.wrap(hbArray);
        cleartextBuf.position(messageLength + ciphertextLength);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        cipher.doFinal(ciphertextBuf, cleartextBuf);
        int cleartextLength = cleartextBuf.position() - messageLength - ciphertextLength;
        cleartextBuf.limit(cleartextBuf.position() );
        cleartextBuf.position(messageLength + ciphertextLength);

        byte[] cleartext = new byte[cleartextLength];
        cleartextBuf.get(cleartext);
        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testGCMModeWithDirectByteBuffer() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        GCMParameterSpec paramSpec = new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, GCM_IV);
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);

        ByteBuffer messageBuf = ByteBuffer.allocateDirect(MESSAGE.length);
        messageBuf.put(MESSAGE);
        messageBuf.flip();
        ByteBuffer ciphertextBuf = ByteBuffer.allocateDirect(128);
        cipher.doFinal(messageBuf, ciphertextBuf);
        ciphertextBuf.flip();

        ByteBuffer cleartextBuf = ByteBuffer.allocateDirect(MESSAGE.length);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        cipher.doFinal(ciphertextBuf, cleartextBuf);

        int length = cleartextBuf.position();
        cleartextBuf.flip();

        byte[] cleartext = new byte[length];
        cleartextBuf.get(cleartext, 0, length);
        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testGCMModeTagMismatchWithDirectByteBuffer() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        GCMParameterSpec paramSpec = new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, GCM_IV);
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);

        ByteBuffer ciphertextBuf = ByteBuffer.allocateDirect(32);
        ByteBuffer cleartextBuf = ByteBuffer.allocateDirect(32);
        Assertions.assertThrows(AEADBadTagException.class,
                () -> cipher.doFinal(ciphertextBuf, cleartextBuf));
    }

    @Test
    public void testGCMModeParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testGCMMode();
            return null;
        });
    }

    @Test
    public void testGCMModeSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testGCMMode();
            return null;
        });
    }

    @Test
    public void testReInit() throws Exception {
        testReInit("SM4/CBC/NoPadding", new IvParameterSpec(IV));
        testReInit("SM4/CBC/PKCS7Padding", new IvParameterSpec(IV));
        testReInit("SM4/CTR/NoPadding", new IvParameterSpec(IV));
        testReInit("SM4/ECB/NoPadding", null);
        testReInit("SM4/ECB/PKCS7Padding", null);
        testReInit("SM4/GCM/NoPadding", new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, GCM_IV));
    }

    private void testReInit(String algorithm,
                            AlgorithmParameterSpec paramSpec) throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        SecretKey altSecretKey = new SecretKeySpec(
                toBytes("01234567012345670123456701234567"), "SM4");

        Cipher cipher = Cipher.getInstance(algorithm, PROVIDER);

        if (paramSpec != null) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
            cipher.init(Cipher.ENCRYPT_MODE, altSecretKey, paramSpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            cipher.init(Cipher.ENCRYPT_MODE, altSecretKey);
        }
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        if (paramSpec != null) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
            cipher.init(Cipher.DECRYPT_MODE, altSecretKey, paramSpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            cipher.init(Cipher.DECRYPT_MODE, altSecretKey);
        }
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testReuse() throws Exception {
        if (PROVIDER instanceof KonaCryptoNativeOneShotProvider) {
            System.out.println("SM4OneShotCipher cannot be reused");
            return;
        }

        testReuse("SM4/CBC/NoPadding", new IvParameterSpec(IV));
        testReuse("SM4/CBC/PKCS7Padding", new IvParameterSpec(IV));
        testReuse("SM4/CTR/NoPadding", new IvParameterSpec(IV));
        testReuse("SM4/ECB/NoPadding", null);
        testReuse("SM4/ECB/PKCS7Padding", null);
    }

    private void testReuse(String algorithm,
            AlgorithmParameterSpec paramSpec) throws Exception {
        byte[] message1 = "0123456789abcdef".getBytes();
        byte[] message2 = "0123456789ABCDEF".getBytes();

        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");

        Cipher cipher = Cipher.getInstance(algorithm, PROVIDER);

        if (paramSpec != null) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }
        byte[] ciphertext1 = cipher.doFinal(message1);
        byte[] ciphertext2 = cipher.doFinal(message2);

        if (paramSpec != null) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        }
        byte[] cleartext1 = cipher.doFinal(ciphertext1);
        byte[] cleartext2 = cipher.doFinal(ciphertext2);

        Assertions.assertArrayEquals(message1, cleartext1);
        Assertions.assertArrayEquals(message2, cleartext2);
    }

    @Test
    public void testReuseGCM() throws Exception {
        byte[] message1 = "0123456789abcdef".getBytes();
        byte[] message2 = "0123456789ABCDEF".getBytes();

        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");

        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey,
                new GCMParameterSpec(SM4_GCM_TAG_LEN * 8, GCM_IV));
        byte[] ciphertext1 = cipher.doFinal(message1);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey,
                new GCMParameterSpec(SM4_GCM_TAG_LEN * 8, ALT_GCM_IV));
        byte[] ciphertext2 = cipher.doFinal(message2);

        cipher.init(Cipher.DECRYPT_MODE, secretKey,
                new GCMParameterSpec(SM4_GCM_TAG_LEN * 8, GCM_IV));
        byte[] cleartext1 = cipher.doFinal(ciphertext1);

        cipher.init(Cipher.DECRYPT_MODE, secretKey,
                new GCMParameterSpec(SM4_GCM_TAG_LEN * 8, ALT_GCM_IV));
        byte[] cleartext2 = cipher.doFinal(ciphertext2);

        Assertions.assertArrayEquals(message1, cleartext1);
        Assertions.assertArrayEquals(message2, cleartext2);
    }

    @Test
    public void testReusedIv4GCMCipher() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        GCMParameterSpec paramSpec = new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, GCM_IV);
        GCMParameterSpec altParamSpec = new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, toBytes("012345012345012345012345"));

        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        // Init encrypter with same key and IV is NOT acceptable.
        Assertions.assertThrows(
                InvalidAlgorithmParameterException.class,
                () -> cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec));
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, altParamSpec);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        // Init decrypter with same key and IV is acceptable.
        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, altParamSpec);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testGCMWithBadTag() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        GCMParameterSpec paramSpec = new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, GCM_IV);

        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        // Change the tag bytes
        ciphertext[ciphertext.length - 1] = 0x00;
        ciphertext[ciphertext.length - 2] = 0x00;

        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        Assertions.assertThrows(AEADBadTagException.class,
                () -> cipher.doFinal(ciphertext));
    }

    @Test
    public void testUpdateData() throws Exception {
        testUpdateData("SM4/CBC/NoPadding", new IvParameterSpec(IV), true);
        testUpdateData("SM4/CBC/NoPadding", new IvParameterSpec(IV), false);

        testUpdateData("SM4/CBC/PKCS7Padding", new IvParameterSpec(IV), true);
        testUpdateData("SM4/CBC/PKCS7Padding", new IvParameterSpec(IV), false);

        testUpdateData("SM4/ECB/NoPadding", null, true);
        testUpdateData("SM4/ECB/NoPadding", null, false);

        testUpdateData("SM4/ECB/PKCS7Padding", null, true);
        testUpdateData("SM4/ECB/PKCS7Padding", null, false);

        testUpdateData("SM4/CTR/NoPadding", new IvParameterSpec(IV), true);
        testUpdateData("SM4/CTR/NoPadding", new IvParameterSpec(IV), false);

        testUpdateData("SM4/GCM/NoPadding", new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, GCM_IV), true);
        testUpdateData("SM4/GCM/NoPadding", new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, GCM_IV), false);
    }

    private void testUpdateData(String algorithm,
                                AlgorithmParameterSpec paramSpec,
                                boolean segmentedEnc) throws Exception {
        byte[] ciphertext = cipherData(algorithm, Cipher.ENCRYPT_MODE,
                paramSpec, MESSAGE, segmentedEnc);
        byte[] cleartext = cipherData(algorithm, Cipher.DECRYPT_MODE,
                paramSpec, ciphertext, !segmentedEnc);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    private byte[] cipherData(String algorithm, int opmode,
                                AlgorithmParameterSpec paramSpec,
                                byte[] data, boolean segmented)
            throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        Cipher cipher = Cipher.getInstance(algorithm, PROVIDER);
        if (paramSpec != null) {
            cipher.init(opmode, secretKey, paramSpec);
        } else {
            cipher.init(opmode, secretKey);
        }

        byte[] cipherData;
        if (segmented) {
            byte[] firstData = TestUtils.null2Empty(cipher.update(data, 0, data.length / 2));
            byte[] secondData = TestUtils.null2Empty(cipher.update(data, data.length / 2,
                    data.length - data.length / 2));
            byte[] finalData = TestUtils.null2Empty(cipher.doFinal());

            cipherData = new byte[firstData.length + secondData.length + finalData.length];
            if (firstData.length > 0) {
                System.arraycopy(
                        firstData, 0,
                        cipherData, 0,
                        firstData.length);
            }
            if (secondData.length > 0) {
                System.arraycopy(
                        secondData, 0,
                        cipherData, firstData.length,
                        secondData.length);
            }
            if (finalData.length > 0) {
                System.arraycopy(
                        finalData, 0,
                        cipherData, firstData.length + secondData.length,
                        finalData.length);
            }
        } else {
            cipherData = cipher.doFinal(data);
        }

        return cipherData;
    }

    @Test
    public void testUpdateAAD() throws Exception {
        testUpdateAAD(true);
        testUpdateAAD(false);
    }

    private void testUpdateAAD(boolean segmentedEnc) throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        GCMParameterSpec paramSpec = new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, GCM_IV);
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
        if (segmentedEnc) {
            cipher.updateAAD(AAD, 0, AAD.length / 2);
            cipher.updateAAD(AAD, AAD.length / 2, AAD.length - AAD.length / 2);
        } else {
            cipher.updateAAD(AAD);
        }
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
        if (!segmentedEnc) {
            cipher.updateAAD(AAD, 0, AAD.length / 2);
            cipher.updateAAD(AAD, AAD.length / 2, AAD.length - AAD.length / 2);
        } else {
            cipher.updateAAD(AAD);
        }
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testUpdateAADExceptionEncUpdate() {
        Assertions.assertThrows(IllegalStateException.class,
                () -> testUpdateAADException(Cipher.ENCRYPT_MODE, true));
        Assertions.assertThrows(IllegalStateException.class,
                () -> testUpdateAADException(Cipher.ENCRYPT_MODE, false));
        Assertions.assertThrows(IllegalStateException.class,
                () -> testUpdateAADException(Cipher.DECRYPT_MODE, true));
        Assertions.assertThrows(AEADBadTagException.class,
                () -> testUpdateAADException(Cipher.DECRYPT_MODE, false));
    }

    private void testUpdateAADException(int opmode, boolean doUpdate)
            throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");
        GCMParameterSpec paramSpec = new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, GCM_IV);
        Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", PROVIDER);

        cipher.init(opmode, secretKey, paramSpec);
        cipher.updateAAD(AAD);
        if (doUpdate) {
            cipher.update(MESSAGE);
        } else {
            cipher.doFinal();
        }
        cipher.updateAAD(AAD);
    }

    @Test
    public void testKeyWrapping() throws Exception {
        testKeyWrapping("SM4/ECB/NoPadding");
        testKeyWrapping("SM4/ECB/PKCS7Padding");
    }

    private void testKeyWrapping(String algorithm) throws Exception {
        Cipher wrapper = Cipher.getInstance(algorithm, PROVIDER);
        Cipher cipher = Cipher.getInstance(algorithm, PROVIDER);

        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", PROVIDER);
        keyGen.init(128);

        // Generate two keys: secretKey and sessionKey
        SecretKey secretKey = keyGen.generateKey();
        SecretKey sessionKey = keyGen.generateKey();

        // Wrap and unwrap the session key make sure the unwrapped session key
        // can decrypt a message encrypted with the session key.
        wrapper.init(Cipher.WRAP_MODE, secretKey);
        byte[] wrappedKey = wrapper.wrap(sessionKey);

        wrapper.init(Cipher.UNWRAP_MODE, secretKey);
        SecretKey unwrappedSessionKey =
                (SecretKey) wrapper.unwrap(wrappedKey, "SM4", Cipher.SECRET_KEY);

        cipher.init(Cipher.ENCRYPT_MODE, unwrappedSessionKey);

        byte[] ciphertext = cipher.doFinal(MESSAGE);
        cipher.init(Cipher.DECRYPT_MODE, unwrappedSessionKey);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testSealedObject() throws Exception {
        KeyPairGenerator keyPairGen
                = KeyPairGenerator.getInstance("EC", PROVIDER);
        keyPairGen.initialize(256);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        // Create SM4 key
        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", PROVIDER);
        SecretKey secretKey = keyGen.generateKey();

        // Create cipher
        Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Seal the private key
        SealedObject sealed = new SealedObject(keyPair.getPrivate(), cipher);

        // Serialize
        try (FileOutputStream fos = new FileOutputStream("sealed");
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(sealed);
        }

        String fileName = "sealed";

        // Deserialize
        try (FileInputStream fis = new FileInputStream(fileName);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            sealed = (SealedObject) ois.readObject();
        }

        // Compare unsealed private key with original
        PrivateKey priKey = (PrivateKey) sealed.getObject(secretKey);

        // Clean
        Files.deleteIfExists(Paths.get(fileName));

        Assertions.assertEquals(keyPair.getPrivate(), priKey);
    }

    @Test
    public void testCipherStream() throws Exception {
        testCipherStream("SM4/CBC/NoPadding", new IvParameterSpec(IV));
        testCipherStream("SM4/CBC/PKCS7Padding", new IvParameterSpec(IV));
        testCipherStream("SM4/CTR/NoPadding", new IvParameterSpec(IV));
        testCipherStream("SM4/ECB/NoPadding", null);
        testCipherStream("SM4/ECB/PKCS7Padding", null);
        testCipherStream("SM4/GCM/NoPadding", new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, GCM_IV));
    }

    private void testCipherStream(String algorithm,
                                  AlgorithmParameterSpec paramSpec)
            throws Exception {
        Key key = new SecretKeySpec(KEY, "SM4");

        Cipher encrypter = Cipher.getInstance(algorithm, PROVIDER);
        if (paramSpec != null) {
            encrypter.init(Cipher.ENCRYPT_MODE, key, paramSpec);
        } else {
            encrypter.init(Cipher.ENCRYPT_MODE, key);
        }

        ByteArrayOutputStream ciphertextOut = new ByteArrayOutputStream();
        try (CipherOutputStream encryptOut = new CipherOutputStream(
                ciphertextOut, encrypter)) {
            for (int i = 0; i < MESSAGE.length / 2; i++) {
                encryptOut.write(MESSAGE[i]);
            }
            encryptOut.write(MESSAGE, MESSAGE.length / 2,
                    MESSAGE.length - MESSAGE.length / 2);
        }

        Cipher decrypter = Cipher.getInstance(algorithm, PROVIDER);
        if (paramSpec != null) {
            decrypter.init(Cipher.DECRYPT_MODE, key, paramSpec);
        } else {
            decrypter.init(Cipher.DECRYPT_MODE, key);
        }

        byte[] cleartext = new byte[MESSAGE.length];
        ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(
                ciphertextOut.toByteArray());
        try (CipherInputStream decryptIn = new CipherInputStream(
                ciphertextIn, decrypter)) {
            DataInputStream dataIn = new DataInputStream(decryptIn);
            for (int i = 0; i < MESSAGE.length / 2; i++) {
                cleartext[i] = (byte) dataIn.read();
            }
            dataIn.readFully(cleartext, MESSAGE.length / 2,
                    MESSAGE.length - MESSAGE.length / 2);
        }

        Assertions.assertArrayEquals(cleartext, MESSAGE);
    }

    @Test
    public void testGetOutputSize() throws Exception {
        SecretKey key = new SecretKeySpec(KEY, "SM4");
        IvParameterSpec ivParamSpec = new IvParameterSpec(IV);

        Cipher cipherCBCNoPadding = Cipher.getInstance("SM4/CBC/NoPadding",
                PROVIDER);
        cipherCBCNoPadding.init(Cipher.ENCRYPT_MODE, key, ivParamSpec);
        Assertions.assertEquals(16, cipherCBCNoPadding.getOutputSize(16));

        Cipher cipherCBCPadding = Cipher.getInstance("SM4/CBC/PKCS7Padding",
                PROVIDER);
        cipherCBCPadding.init(Cipher.ENCRYPT_MODE, key, ivParamSpec);
        Assertions.assertEquals(16, cipherCBCPadding.getOutputSize(15));
        Assertions.assertEquals(32, cipherCBCPadding.getOutputSize(16));

        Cipher cipherCTRNoPadding = Cipher.getInstance("SM4/CTR/NoPadding",
                PROVIDER);
        cipherCTRNoPadding.init(Cipher.ENCRYPT_MODE, key, ivParamSpec);
        Assertions.assertEquals(15, cipherCTRNoPadding.getOutputSize(15));
        Assertions.assertEquals(16, cipherCTRNoPadding.getOutputSize(16));

        Cipher cipherECBNoPadding = Cipher.getInstance("SM4/ECB/NoPadding",
                PROVIDER);
        cipherECBNoPadding.init(Cipher.ENCRYPT_MODE, key);
        Assertions.assertEquals(16, cipherECBNoPadding.getOutputSize(16));

        Cipher cipherECBPKCS7Padding = Cipher.getInstance("SM4/ECB/PKCS7Padding",
                PROVIDER);
        cipherECBPKCS7Padding.init(Cipher.ENCRYPT_MODE, key);
        Assertions.assertEquals(16, cipherECBPKCS7Padding.getOutputSize(15));
        Assertions.assertEquals(32, cipherECBPKCS7Padding.getOutputSize(16));

        Cipher cipherGCMNoPadding = Cipher.getInstance("SM4/GCM/NoPadding",
                PROVIDER);
        cipherGCMNoPadding.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(
                SM4_GCM_TAG_LEN * 8, GCM_IV));
        Assertions.assertEquals(31, cipherGCMNoPadding.getOutputSize(15));
        Assertions.assertEquals(32, cipherGCMNoPadding.getOutputSize(16));
    }
}
