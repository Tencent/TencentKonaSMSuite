/*
 * Copyright (C) 2022, 2024, Tencent. All rights reserved.
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

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The test for SM3 HMAC with BouncyCastle.
 */
public class SM3HMacWithBCTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testSM3HMac() throws Exception {
        byte[] message = toBytes("616263");

        Mac sm3HMac = Mac.getInstance("HmacSM3", PROVIDER);
        Mac sm3HMacBC = Mac.getInstance("HMACSM3", "BC");

        SecretKey secretKey = new SecretKeySpec(
                toBytes("0123456789abcdef0123456789abcdef"), "SM4");

        sm3HMac.init(secretKey);
        sm3HMacBC.init(secretKey);

        byte[] mac = sm3HMac.doFinal(message);
        byte[] macBC = sm3HMacBC.doFinal(message);

        Assertions.assertArrayEquals(macBC, mac);
    }
}
