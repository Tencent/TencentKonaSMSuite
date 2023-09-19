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
import com.tencent.kona.crypto.util.Constants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.util.Random;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The test for SM3 digest and mac.
 */
public class SM3Test {

    private static final byte[] MESSAGE_SHORT = toBytes("616263");
    private static final byte[] DIGEST_SHORT = toBytes(
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");

    private static final byte[] MESSAGE_LONG = toBytes(
            "61626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364");
    private static final byte[] DIGEST_LONG = toBytes(
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testKAT() throws Exception {
        checkDigest(MESSAGE_SHORT, DIGEST_SHORT);
        checkDigest(MESSAGE_LONG, DIGEST_LONG);
    }

    private static void checkDigest(byte[] message, byte[] expectedDigest)
            throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", PROVIDER);
        byte[] digest = md.digest(message);
        Assertions.assertArrayEquals(expectedDigest, digest);
    }

    @Test
    public void testGetDigestLength() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", PROVIDER);
        int digestLength = md.getDigestLength();
        Assertions.assertEquals(32, digestLength);
    }

    @Test
    public void testUpdateByte() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", PROVIDER);

        for (byte b : MESSAGE_SHORT) {
            md.update(b);
        }
        byte[] digest= md.digest();

        Assertions.assertArrayEquals(DIGEST_SHORT, digest);
    }

    @Test
    public void testUpdateBytes() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", PROVIDER);

        md.update(MESSAGE_SHORT, 0, MESSAGE_SHORT.length / 2);
        md.update(MESSAGE_SHORT, MESSAGE_SHORT.length / 2,
                MESSAGE_SHORT.length - MESSAGE_SHORT.length / 2);
        byte[] digest = md.digest();

        Assertions.assertArrayEquals(DIGEST_SHORT, digest);
    }

    @Test
    public void testBigData() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", PROVIDER);
        byte[] digest = md.digest(TestUtils.dataMB(10));
        Assertions.assertEquals(Constants.SM3_DIGEST_LEN, digest.length);
    }

    @Test
    public void testReset() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", PROVIDER);

        md.update(MESSAGE_SHORT, 0, MESSAGE_SHORT.length / 2);
        md.reset();
        md.update(MESSAGE_SHORT, 0, MESSAGE_SHORT.length / 2);
        md.update(MESSAGE_SHORT, MESSAGE_SHORT.length / 2,
                MESSAGE_SHORT.length - MESSAGE_SHORT.length / 2);
        byte[] digest = md.digest();

        Assertions.assertArrayEquals(DIGEST_SHORT, digest);
    }

    @Test
    public void testKATParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testKAT();
            return null;
        });
    }

    @Test
    public void testKATSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testKAT();
            return null;
        });
    }

    @Test
    public void testOutOfBounds() throws Exception {
        outOfBounds(16, 0, 32);
        outOfBounds(7, 0, 32);
        outOfBounds(16, -8, 16);
        outOfBounds(16, 8, -8);
        outOfBounds(16, Integer.MAX_VALUE, 8);
    }

    private static void outOfBounds(int arrayLen, int ofs, int len)
            throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", PROVIDER);

        try {
            md.update(new byte[arrayLen], ofs, len);
            throw new Exception("invalid call succeeded");
        } catch (RuntimeException e) {
            System.out.println("Expected: " + e);
        }
    }

    @Test
    public void testOffset() throws Exception {
        offset(0, 64, 0, 128);
        offset(0, 64, 0, 129);
        offset(1, 32, 1, 129);
    }

    private static void offset(
            int minOffset, int maxOffset, int minLen, int maxLen)
            throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", PROVIDER);

        Random random = new Random();
        for (int len = minLen; len <= maxLen; len++) {
            byte[] data = new byte[len];
            random.nextBytes(data);
            byte[] digest = null;
            for (int offset = minOffset; offset <= maxOffset; offset++) {
                byte[] offsetData = new byte[len + maxOffset];
                random.nextBytes(offsetData);
                System.arraycopy(data, 0, offsetData, offset, len);
                md.update(offsetData, offset, len);
                byte[] offsetDigest = md.digest();
                if (digest == null) {
                    digest = offsetDigest;
                } else {
                    Assertions.assertArrayEquals(digest, offsetDigest);
                }
            }
        }
    }

    @Test
    public void testClone() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SM3", PROVIDER);
        md.update(MESSAGE_LONG, 0, MESSAGE_LONG.length / 3);
        md.update(MESSAGE_LONG[MESSAGE_LONG.length / 3]);

        MessageDigest clone = (MessageDigest) md.clone();
        clone.update(MESSAGE_LONG, MESSAGE_LONG.length / 3 + 1,
                MESSAGE_LONG.length - MESSAGE_LONG.length / 3 - 2);
        clone.update(MESSAGE_LONG[MESSAGE_LONG.length - 1]);
        byte[] digest = clone.digest();

        Assertions.assertArrayEquals(DIGEST_LONG, digest);
    }
}
