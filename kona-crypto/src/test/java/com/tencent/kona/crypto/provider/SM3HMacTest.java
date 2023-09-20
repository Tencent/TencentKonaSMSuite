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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.nio.ByteBuffer;
import java.security.InvalidParameterException;
import java.security.SecureRandom;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static com.tencent.kona.crypto.util.Constants.SM3_HMAC_LEN;
import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The test for SM3 HMAC.
 */
public class SM3HMacTest {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] MESSAGE = toBytes("616263");

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testSM3HMacKeyGen() throws Exception {
        KeyGenerator sm3HMacKeyGen
                = KeyGenerator.getInstance("HmacSM3", PROVIDER);

        TestUtils.checkThrowable(
                InvalidParameterException.class, ()-> sm3HMacKeyGen.init(127));

        sm3HMacKeyGen.init(128);
        SecretKey key = sm3HMacKeyGen.generateKey();
        Assertions.assertEquals(16, key.getEncoded().length);

        sm3HMacKeyGen.init(new SecureRandom());
        key = sm3HMacKeyGen.generateKey();
        Assertions.assertEquals(32, key.getEncoded().length);
    }

    @Test
    public void testSM3HMacKeyGenParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testSM3HMacKeyGen();
            return null;
        });
    }

    @Test
    public void testSM3HMacKeyGenSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testSM3HMacKeyGen();
            return null;
        });
    }

    @Test
    public void testSM3HMac() throws Exception {
        Mac sm3HMac = Mac.getInstance("HmacSM3", PROVIDER);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "HmacSM3");
        sm3HMac.init(keySpec);
        byte[] mac = sm3HMac.doFinal(toBytes("616263"));
        Assertions.assertEquals(SM3_HMAC_LEN, mac.length);
    }

    @Test
    public void testUpdateByte() throws Exception {
        Mac sm3HMac = Mac.getInstance("HmacSM3", PROVIDER);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "HmacSM3");
        sm3HMac.init(keySpec);
        for (byte b : MESSAGE) {
            sm3HMac.update(b);
        }
        byte[] mac = sm3HMac.doFinal();
        Assertions.assertEquals(SM3_HMAC_LEN, mac.length);
    }

    @Test
    public void testUpdateBytes() throws Exception {
        Mac sm3HMac = Mac.getInstance("HmacSM3", PROVIDER);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "HmacSM3");
        sm3HMac.init(keySpec);
        sm3HMac.update(MESSAGE, 0, MESSAGE.length / 2);
        sm3HMac.update(MESSAGE, MESSAGE.length / 2, MESSAGE.length - MESSAGE.length / 2);
        byte[] mac = sm3HMac.doFinal();
        Assertions.assertEquals(SM3_HMAC_LEN, mac.length);
    }

    @Test
    public void testByteBuffer() throws Exception {
        Mac sm3HMac = Mac.getInstance("HmacSM3", PROVIDER);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "HmacSM3");
        sm3HMac.init(keySpec);
        ByteBuffer buffer = ByteBuffer.wrap(toBytes("616263"));
        sm3HMac.update(buffer);
        byte[] mac = sm3HMac.doFinal();
        Assertions.assertEquals(SM3_HMAC_LEN, mac.length);
    }

    @Test
    public void testBigData() throws Exception {
        Mac sm3HMac = Mac.getInstance("HmacSM3", PROVIDER);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "HmacSM3");
        sm3HMac.init(keySpec);
        byte[] mac = sm3HMac.doFinal(TestUtils.dataMB(10));
        Assertions.assertEquals(SM3_HMAC_LEN, mac.length);
    }

    @Test
    public void testBigByteBuffer() throws Exception {
        byte[] data = TestUtils.dataMB(10);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "HmacSM3");

        Mac sm3HMac = Mac.getInstance("HmacSM3", PROVIDER);
        sm3HMac.init(keySpec);
        byte[] mac = sm3HMac.doFinal(data);

        Mac sm3HMacBuffer = Mac.getInstance("HmacSM3", PROVIDER);
        sm3HMacBuffer.init(keySpec);
        ByteBuffer buffer = ByteBuffer.wrap(data);
        sm3HMacBuffer.update(buffer);
        byte[] macBuffer = sm3HMacBuffer.doFinal();

        Assertions.assertArrayEquals(mac, macBuffer);
    }

    @Test
    public void testSM3HMacParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testSM3HMac();
            return null;
        });
    }

    @Test
    public void testSM3HMacSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testSM3HMac();
            return null;
        });
    }

    @Test
    public void testClone() throws Exception {
        Mac sm3HMac = Mac.getInstance("HmacSM3", PROVIDER);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "HmacSM3");
        sm3HMac.init(keySpec);

        sm3HMac.update(MESSAGE, 0, MESSAGE.length / 3);
        sm3HMac.update(MESSAGE[MESSAGE.length / 3]);

        Mac clone = (Mac) sm3HMac.clone();

        sm3HMac.update(MESSAGE, MESSAGE.length / 3 + 1,
                MESSAGE.length - MESSAGE.length / 3 - 2);
        clone.update(MESSAGE, MESSAGE.length / 3 + 1,
                MESSAGE.length - MESSAGE.length / 3 - 2);

        sm3HMac.update(MESSAGE[MESSAGE.length - 1]);
        clone.update(MESSAGE[MESSAGE.length - 1]);

        byte[] mac = sm3HMac.doFinal();
        byte[] macClone = clone.doFinal();

        Assertions.assertArrayEquals(mac, macClone);
    }
}
