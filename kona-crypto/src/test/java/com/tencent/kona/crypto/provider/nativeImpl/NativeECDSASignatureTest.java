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

import static com.tencent.kona.crypto.provider.nativeImpl.NativeCrypto.*;
import static com.tencent.kona.crypto.util.Constants.*;

/**
 * The test for native EC key pair generator implementation.
 */
@EnabledOnOs({OS.LINUX, OS.MAC})
public class NativeECDSASignatureTest {

    private static final byte[] MESSAGE = "message".getBytes();

    @Test
    public void testECDSASignature() {
        checkECDSASignature(NID_SHA256, NID_SECP256R1);
        checkECDSASignature(NID_SHA384, NID_SECP256R1);
        checkECDSASignature(NID_SHA512, NID_SECP256R1);
        checkECDSASignature(NID_SHA256, NID_SECP384R1);
        checkECDSASignature(NID_SHA384, NID_SECP384R1);
        checkECDSASignature(NID_SHA512, NID_SECP384R1);
        checkECDSASignature(NID_SHA256, NID_SECP521R1);
        checkECDSASignature(NID_SHA384, NID_SECP521R1);
        checkECDSASignature(NID_SHA512, NID_SECP521R1);
        checkECDSASignature(NID_SHA256, NID_CURVESM2);
        checkECDSASignature(NID_SHA384, NID_CURVESM2);
        checkECDSASignature(NID_SHA512, NID_CURVESM2);
    }

    private void checkECDSASignature(int mdNID, int curveNID) {
        try (NativeECKeyPairGen ecKeyPairGen = new NativeECKeyPairGen(curveNID)) {
            Object[] keyPair = ecKeyPairGen.genKeyPair();
            byte[] priKey = (byte[]) keyPair[0];
            byte[] pubKey = (byte[]) keyPair[1];

            byte[] signature = NativeCrypto.ecdsaOneShotSign(
                    mdNID, curveNID, priKey, MESSAGE);

            int verified = NativeCrypto.ecdsaOneShotVerify(
                    mdNID, curveNID, pubKey, MESSAGE, signature);
            Assertions.assertEquals(OPENSSL_SUCCESS, verified);
        }
    }

    @Test
    public void testOneShotECDSASignature() {
        checkOneShotECDSASignature(NID_SHA256, NID_SECP256R1);
        checkOneShotECDSASignature(NID_SHA384, NID_SECP256R1);
        checkOneShotECDSASignature(NID_SHA512, NID_SECP256R1);
        checkOneShotECDSASignature(NID_SHA256, NID_SECP384R1);
        checkOneShotECDSASignature(NID_SHA384, NID_SECP384R1);
        checkOneShotECDSASignature(NID_SHA512, NID_SECP384R1);
        checkOneShotECDSASignature(NID_SHA256, NID_SECP521R1);
        checkOneShotECDSASignature(NID_SHA384, NID_SECP521R1);
        checkOneShotECDSASignature(NID_SHA512, NID_SECP521R1);
        checkOneShotECDSASignature(NID_SHA256, NID_CURVESM2);
        checkOneShotECDSASignature(NID_SHA384, NID_CURVESM2);
        checkOneShotECDSASignature(NID_SHA512, NID_CURVESM2);
    }

    private void checkOneShotECDSASignature(int mdNID, int curveNID) {
        Object[] keyPair = NativeCrypto.ecOneShotKeyPairGenGenKeyPair(curveNID);
        byte[] priKey = (byte[]) keyPair[0];
        byte[] pubKey = (byte[]) keyPair[1];

        byte[] signature = NativeCrypto.ecdsaOneShotSign(
                mdNID, curveNID, priKey, MESSAGE);

        int verified = NativeCrypto.ecdsaOneShotVerify(
                mdNID, curveNID, pubKey, MESSAGE, signature);
        Assertions.assertEquals(OPENSSL_SUCCESS, verified);
    }

    @Test
    public void testECDSASignatureParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testECDSASignature();
            return null;
        });
    }

    @Test
    public void tesOneShotECDSASignatureParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testOneShotECDSASignature();
            return null;
        });
    }

    @Test
    public void testECDSASignatureSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testECDSASignature();
            return null;
        });
    }

    @Test
    public void testOneShotECDSASignatureSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testOneShotECDSASignature();
            return null;
        });
    }
}
