/*
 * Copyright (C) 2024, 2025, Tencent. All rights reserved.
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
 * The test for native SM3 HMAC implementation.
 */
@EnabledOnOs(OS.LINUX)
public class NativeSM3HMacTest {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] ALT_KEY = toBytes("0123456789abcdef0123456789abcd");
    private static final byte[] EMPTY = new byte[0];
    private static final byte[] MESSAGE = toBytes("616263");
    private static final byte[] MAC = toBytes("4d2e8eefcfaa97b2bea04cda000823a4f2e6e264cf7a819d67117ad12cc9a8af");

    @Test
    public void testMac() {
        try(NativeSM3HMac sm3hmac = new NativeSM3HMac(KEY)) {
            sm3hmac.update(MESSAGE);
            byte[] mac = sm3hmac.doFinal();
            Assertions.assertArrayEquals(MAC, mac);
        }
    }

    @Test
    public void testOneShotMac() {
        byte[] mac = NativeCrypto.sm3hmacOneShotMac(KEY, MESSAGE);
        Assertions.assertArrayEquals(MAC, mac);
    }

    @Test
    public void testUpdate() {
        try(NativeSM3HMac sm3hmac = new NativeSM3HMac(KEY)) {

            sm3hmac.update(toBytes("6162"));
            sm3hmac.update(toBytes("63"));
            byte[] mac = sm3hmac.doFinal();

            Assertions.assertArrayEquals(MAC, mac);
        }
    }

    @Test
    public void testReuse() {
        try(NativeSM3HMac sm3hmac = new NativeSM3HMac(KEY)) {
            byte[] mac1 = sm3hmac.doFinal(MESSAGE);
            Assertions.assertArrayEquals(MAC, mac1);

            byte[] mac2 = sm3hmac.doFinal(MESSAGE);
            Assertions.assertArrayEquals(MAC, mac2);
        }
    }

    @Test
    public void testReset() {
        try(NativeSM3HMac sm3hmac = new NativeSM3HMac(KEY)) {

            sm3hmac.update(MESSAGE);
            sm3hmac.reset();
            sm3hmac.update(MESSAGE);
            byte[] mac = sm3hmac.doFinal();

            Assertions.assertArrayEquals(MAC, mac);
        }
    }

    @Test
    public void testClone() {
        try(NativeSM3HMac sm3hmac = new NativeSM3HMac(KEY)) {
            sm3hmac.update(MESSAGE);

            try (NativeSM3HMac clone = sm3hmac.clone()) {
                byte[] mac = clone.doFinal();

                Assertions.assertArrayEquals(MAC, mac);
            }

            byte[] mac = sm3hmac.doFinal();
            Assertions.assertArrayEquals(MAC, mac);
        }
    }

    @Test
    public void testKey() {
        new NativeSM3HMac(ALT_KEY).close();
        Assertions.assertThrows(
                IllegalStateException.class,
                ()-> new NativeSM3HMac(EMPTY).close());
        Assertions.assertThrows(
                IllegalStateException.class,
                ()-> new NativeSM3HMac(null).close());
    }

    @Test
    public void testEmptyData() {
        try(NativeSM3HMac sm3hmac = new NativeSM3HMac(KEY)) {
            byte[] mac = sm3hmac.doFinal(EMPTY);
            Assertions.assertEquals(SM3_HMAC_LEN, mac.length);
        }
    }

    @Test
    public void testNullData() {
        try(NativeSM3HMac sm3hmac = new NativeSM3HMac(KEY)) {
            Assertions.assertThrows(
                    NullPointerException.class,
                    () -> sm3hmac.doFinal(null));
        }
    }

    @Test
    public void testUseClosedRef() {
        NativeSM3HMac sm3hmac = new NativeSM3HMac(KEY);
        sm3hmac.close();

        Assertions.assertThrows(
                IllegalStateException.class,
                () -> sm3hmac.doFinal(MESSAGE));
    }

    @Test
    public void testCloseTwice() {
        NativeSM3HMac sm3hmac = new NativeSM3HMac(KEY);
        sm3hmac.doFinal(MESSAGE);
        sm3hmac.close();
        sm3hmac.close();
    }
}
