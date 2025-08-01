/*
 * Copyright (C) 2022, 2023, Tencent. All rights reserved.
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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The test for SM3 engine.
 */
public class SM3EngineTest {

    private static final byte[] MESSAGE_SHORT = toBytes("616263");
    private static final byte[] DIGEST_SHORT = toBytes(
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");

    private static final byte[] MESSAGE_LONG = toBytes(
            "61626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364");
    private static final byte[] DIGEST_LONG = toBytes(
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");

    @Test
    public void testKAT() {
        testDigest(MESSAGE_SHORT, DIGEST_SHORT);
        testDigest(MESSAGE_LONG, DIGEST_LONG);
    }

    private void testDigest(byte[] message, byte[] expectedDigest) {
        byte[] digest = new byte[32];

        SM3Engine sm3Engine = new SM3Engine();
        sm3Engine.update(message);
        sm3Engine.doFinal(digest);

        Assertions.assertArrayEquals(expectedDigest, digest);
    }

    @Test
    public void testUpdateBulk() {
        testUpdateBulk(MESSAGE_SHORT, DIGEST_SHORT);
        testUpdateBulk(MESSAGE_LONG, DIGEST_LONG);
    }

    private void testUpdateBulk(byte[] message, byte[] expectedDigest) {
        byte[] digest = new byte[32];

        SM3Engine sm3Engine = new SM3Engine();
        sm3Engine.update(message, 0, message.length / 3);
        sm3Engine.update(message, message.length / 3, message.length / 3);
        sm3Engine.update(message, message.length / 3 * 2, message.length - message.length / 3 * 2);
        sm3Engine.doFinal(digest);

        Assertions.assertArrayEquals(expectedDigest, digest);
    }

    @Test
    public void testUpdate() {
        testUpdate(MESSAGE_SHORT, DIGEST_SHORT);
        testUpdate(MESSAGE_LONG, DIGEST_LONG);
    }

    private void testUpdate(byte[] message, byte[] expectedDigest) {
        byte[] digest = new byte[32];

        SM3Engine sm3Engine = new SM3Engine();
        for(byte b : message) {
            sm3Engine.update(b);
        }
        sm3Engine.doFinal(digest);

        Assertions.assertArrayEquals(expectedDigest, digest);
    }
}
