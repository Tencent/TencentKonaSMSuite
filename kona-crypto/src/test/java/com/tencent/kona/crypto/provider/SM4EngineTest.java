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

/**
 * The test for SM4 engine.
 */
public class SM4EngineTest {

    private static final byte[] KEY = {
            (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
            (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
            (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98,
            (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10
    };

    private static final byte[] PLAINTEXT = {
            (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
            (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
            (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98,
            (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10
    };

    private static final byte[] CIPHERTEXT = {
            (byte)0x68, (byte)0x1e, (byte)0xdf, (byte)0x34,
            (byte)0xd2, (byte)0x06, (byte)0x96, (byte)0x5e,
            (byte)0x86, (byte)0xb3, (byte)0xe9, (byte)0x4f,
            (byte)0x53, (byte)0x6e, (byte)0x42, (byte)0x46
    };

    private static final byte[] REPEATED_CIPHERTEXT = {
            (byte)0x59, (byte)0x52, (byte)0x98, (byte)0xc7,
            (byte)0xc6, (byte)0xfd, (byte)0x27, (byte)0x1f,
            (byte)0x04, (byte)0x02, (byte)0xf8, (byte)0x04,
            (byte)0xc3, (byte)0x3d, (byte)0x3f, (byte)0x66
    };

    @Test
    public void testEncryption() {
        SM4Engine engine = new SM4Engine(KEY, true);
        byte[] ciphertext = new byte[16];
        engine.processBlock(PLAINTEXT, 0, ciphertext, 0);
        Assertions.assertArrayEquals(CIPHERTEXT, ciphertext);
    }

    @Test
    public void testDecryption() {
        SM4Engine engine = new SM4Engine(KEY, false);
        byte[] cleartext = new byte[16];
        engine.processBlock(CIPHERTEXT, 0, cleartext, 0);
        Assertions.assertArrayEquals(PLAINTEXT, cleartext);
    }

    @Test
    public void testEncryptMillionTimes() {
        SM4Engine engine = new SM4Engine(KEY, true);
        byte[] ciphertext = new byte[16];
        engine.processBlock(PLAINTEXT, 0, ciphertext, 0);
        for (int i = 1; i < 1_000_000; i++) {
            engine.processBlock(ciphertext, 0, ciphertext, 0);
        }
        Assertions.assertArrayEquals(REPEATED_CIPHERTEXT, ciphertext);
    }

    @Test
    public void testDecryptMillionTimes() {
        SM4Engine engine = new SM4Engine(KEY, false);
        byte[] cleartext = new byte[16];
        engine.processBlock(REPEATED_CIPHERTEXT, 0, cleartext, 0);
        for (int i = 1; i < 1_000_000; i++) {
            engine.processBlock(cleartext, 0, cleartext, 0);
        }
        Assertions.assertArrayEquals(PLAINTEXT, cleartext);
    }
}
