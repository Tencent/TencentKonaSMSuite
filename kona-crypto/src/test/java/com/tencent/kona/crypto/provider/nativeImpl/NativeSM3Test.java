/*
 * Copyright (C) 2024, THL A29 Limited, a Tencent company. All rights reserved.
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

package com.tencent.kona.crypto.provider.nativeImpl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.util.Constants.*;

/**
 * The test for native SM3 implementation.
 */
@EnabledOnOs(OS.LINUX)
public class NativeSM3Test {

    private static final byte[] MESSAGE_0 = new byte[0];

    private static final byte[] MESSAGE_SHORT = toBytes("616263");
    private static final byte[] DIGEST_SHORT = toBytes(
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");

    private static final byte[] MESSAGE_LONG = toBytes(
            "61626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364");
    private static final byte[] DIGEST_LONG = toBytes(
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");

    static {
        NativeCrypto.loadLibs();
    }

    @Test
    public void testKAT() {
        checkDigest(MESSAGE_SHORT, DIGEST_SHORT);
        checkDigest(MESSAGE_LONG, DIGEST_LONG);
    }

    private static void checkDigest(byte[] message, byte[] expectedDigest) {
        try(NativeSM3 sm3 = new NativeSM3()) {
            sm3.update(message);
            byte[] digest = sm3.doFinal();
            Assertions.assertArrayEquals(expectedDigest, digest);
        }
    }

    @Test
    public void testUpdate() {
        try(NativeSM3 sm3 = new NativeSM3()) {

            sm3.update(toBytes("6162"));
            sm3.update(toBytes("63"));
            byte[] digest = sm3.doFinal();

            Assertions.assertArrayEquals(DIGEST_SHORT, digest);
        }
    }

    @Test
    public void testReuse() {
        try(NativeSM3 sm3 = new NativeSM3()) {
            byte[] digest1 = sm3.doFinal(MESSAGE_SHORT);
            Assertions.assertArrayEquals(DIGEST_SHORT, digest1);

            byte[] digest2 = sm3.doFinal(MESSAGE_SHORT);
            Assertions.assertArrayEquals(DIGEST_SHORT, digest2);
        }
    }

    @Test
    public void testReset() {
        try(NativeSM3 sm3 = new NativeSM3()) {

            sm3.update(MESSAGE_SHORT);
            sm3.reset();
            sm3.update(MESSAGE_SHORT);
            byte[] digest = sm3.doFinal();

            Assertions.assertArrayEquals(DIGEST_SHORT, digest);
        }
    }

    @Test
    public void testClone() {
        try(NativeSM3 sm3 = new NativeSM3()) {
            sm3.update(MESSAGE_SHORT);

            try (NativeSM3 clone = sm3.clone()) {
                byte[] digest = clone.doFinal();

                Assertions.assertArrayEquals(DIGEST_SHORT, digest);
            }
        }
    }

    @Test
    public void testEmptyData() {
        try(NativeSM3 sm3 = new NativeSM3()) {
            byte[] digest = sm3.doFinal(MESSAGE_0);
            Assertions.assertEquals(SM3_DIGEST_LEN, digest.length);
        }
    }

    @Test
    public void testNullData() {
        try(NativeSM3 sm3 = new NativeSM3()) {
            Assertions.assertThrows(
                    NullPointerException.class,
                    () -> sm3.doFinal(null));
        }
    }
}
