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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.Security;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The test for SM3 with BouncyCastle.
 */
public class SM3WithBCTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testDigest() throws Exception {
        byte[] message = toBytes("616263");

        MessageDigest md = MessageDigest.getInstance("SM3", PROVIDER);
        byte[] digest = md.digest(message);

        MessageDigest mdBC = MessageDigest.getInstance("SM3", "BC");
        byte[] digestBC = mdBC.digest(message);

        Assertions.assertArrayEquals(digestBC, digest);
    }
}
