/*
 * Copyright (C) 2025, Tencent. All rights reserved.
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
 * The test for native ECDH key agreement implementation.
 */
@EnabledOnOs({OS.LINUX, OS.MAC})
public class NativeECDHKeyAgreementTest {

    @Test
    public void testECDHDeriveKey() {
        checkECDHDeriveKey(NID_SECP256R1);
        checkECDHDeriveKey(NID_SECP384R1);
        checkECDHDeriveKey(NID_SECP521R1);
        checkECDHDeriveKey(NID_CURVESM2);
    }

    private void checkECDHDeriveKey(int curveNID) {
        try (NativeECKeyPairGen ecKeyPairGen = new NativeECKeyPairGen(curveNID)) {
            Object[] keyPair = ecKeyPairGen.genKeyPair();
            byte[] priKey = (byte[]) keyPair[0];
            byte[] pubKey = (byte[]) keyPair[1];

            Object[] peerKeyPair = ecKeyPairGen.genKeyPair();
            byte[] peerPriKey = (byte[]) peerKeyPair[0];
            byte[] peerPubKey = (byte[]) peerKeyPair[1];

            try (NativeECDHKeyAgreement ka = new NativeECDHKeyAgreement(curveNID, priKey)) {
                byte[] sharedKey = ka.deriveKey(peerPubKey);
                try (NativeECDHKeyAgreement peerKA = new NativeECDHKeyAgreement(curveNID, peerPriKey)) {
                    byte[] peerSharedKey = peerKA.deriveKey(pubKey);

                    Assertions.assertNotNull(sharedKey);
                    Assertions.assertArrayEquals(sharedKey, peerSharedKey);
                }
            }
        }
    }

    @Test
    public void testECDHOneShotDeriveKey() {
        checkECDHOneShotDeriveKey(NID_SECP256R1);
        checkECDHOneShotDeriveKey(NID_SECP384R1);
        checkECDHOneShotDeriveKey(NID_SECP521R1);
        checkECDHOneShotDeriveKey(NID_CURVESM2);
    }

    private void checkECDHOneShotDeriveKey(int curveNID) {
        try (NativeECKeyPairGen ecKeyPairGen = new NativeECKeyPairGen(curveNID)) {
            Object[] keyPair = ecKeyPairGen.genKeyPair();
            byte[] priKey = (byte[]) keyPair[0];
            byte[] pubKey = (byte[]) keyPair[1];

            Object[] peerKeyPair = ecKeyPairGen.genKeyPair();
            byte[] peerPriKey = (byte[]) peerKeyPair[0];
            byte[] peerPubKey = (byte[]) peerKeyPair[1];

            byte[] sharedKey = ecdhOneShotDeriveKey(curveNID, priKey, peerPubKey);
            byte[] peerSharedKey = ecdhOneShotDeriveKey(curveNID, peerPriKey, pubKey);

            Assertions.assertNotNull(sharedKey);
            Assertions.assertArrayEquals(sharedKey, peerSharedKey);
        }
    }

    @Test
    public void testECDHDeriveKeyParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testECDHDeriveKey();
            return null;
        });
    }

    @Test
    public void tesOneShotECDSASignatureParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testECDHOneShotDeriveKey();
            return null;
        });
    }

    @Test
    public void testECDHDeriveKeySerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testECDHDeriveKey();
            return null;
        });
    }

    @Test
    public void testECDHOneShotDeriveKeySerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testECDHOneShotDeriveKey();
            return null;
        });
    }
}
