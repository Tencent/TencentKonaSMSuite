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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.InvalidParameterException;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;

/**
 * The test for SM3 HMAC key generator.
 */
public class SM3HMacKeyGeneratorTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testKeyGen() throws Exception {
        testKeyGen("HmacSM3");
    }

    @Test
    public void testAlias() throws Exception {
        testKeyGen("SM3Hmac");
    }

    private void testKeyGen(String name) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(name, PROVIDER);

        Assertions.assertThrows(
                InvalidParameterException.class, ()-> keyGen.init(127));

        SecretKey key = keyGen.generateKey();
        Assertions.assertEquals(32, key.getEncoded().length);

        keyGen.init(128);
        key = keyGen.generateKey();
        Assertions.assertEquals(16, key.getEncoded().length);

        keyGen.init(192);
        key = keyGen.generateKey();
        Assertions.assertEquals(24, key.getEncoded().length);

        keyGen.init(191);
        key = keyGen.generateKey();
        Assertions.assertEquals(24, key.getEncoded().length);
    }

    @Test
    public void testKeyGenParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testKeyGen();
            return null;
        });
    }

    @Test
    public void testKeyGenSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testKeyGen();
            return null;
        });
    }
}
