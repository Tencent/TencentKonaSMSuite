/*
 * Copyright (C) 2025, THL A29 Limited, a Tencent company. All rights reserved.
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

import com.tencent.kona.crypto.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import static com.tencent.kona.crypto.util.Constants.*;

/**
 * The test for native EC key pair generator implementation.
 */
@EnabledOnOs(OS.MAC)
public class NativeECKeyPairGeneratorTest {

    @Test
    public void testECKeyPairGenGenKeyPair() {
        checkECKeyPairGenGenKeyPair(NID_SECP256R1, 32);
        checkECKeyPairGenGenKeyPair(NID_SECP384R1, 48);
        checkECKeyPairGenGenKeyPair(NID_SECP521R1, 66);
        checkECKeyPairGenGenKeyPair(NID_CURVESM2, 32);
    }

    private void checkECKeyPairGenGenKeyPair(int curveNID, int keySize) {
        try (NativeECKeyPairGen ecKeyPairGen = new NativeECKeyPairGen(curveNID)) {
            Object[] keyPair = ecKeyPairGen.genKeyPair();
            Assertions.assertEquals(keySize, (((byte[]) keyPair[0]).length));
        }
    }

    @Test
    public void testOneShotECKeyPairGenGenKeyPair() {
        checkOneShotECKeyPairGenGenKeyPair(NID_SECP256R1, 32);
        checkOneShotECKeyPairGenGenKeyPair(NID_SECP384R1, 48);
        checkOneShotECKeyPairGenGenKeyPair(NID_SECP521R1, 66);
        checkOneShotECKeyPairGenGenKeyPair(NID_CURVESM2, 32);
    }

    private void checkOneShotECKeyPairGenGenKeyPair(int curveNID, int keySize) {
        Object[] keyPair = NativeCrypto.ecOneShotKeyPairGenGenKeyPair(curveNID);
        Assertions.assertEquals(keySize, (((byte[]) keyPair[0]).length));
    }

    @Test
    public void testECKeyPairGenGenKeyPairParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testECKeyPairGenGenKeyPair();
            return null;
        });
    }

    @Test
    public void tesOneShotECKeyPairGenGenKeyPairParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testOneShotECKeyPairGenGenKeyPair();
            return null;
        });
    }

    @Test
    public void testECKeyPairGenGenKeyPairSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testECKeyPairGenGenKeyPair();
            return null;
        });
    }

    @Test
    public void testOneShotECKeyPairGenGenKeyPairSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testOneShotECKeyPairGenGenKeyPair();
            return null;
        });
    }
}
