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

import com.tencent.kona.crypto.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import static com.tencent.kona.crypto.CryptoUtils.*;
import static com.tencent.kona.crypto.util.Constants.*;

/**
 * The test for native SM2 implementation.
 */
@EnabledOnOs(OS.LINUX)
public class NativeSM2Test {

    private final static String PUB_KEY_ODD
            = "0475C05A9371F2CED4573FB2CFD10A36C00294F34582BCBA257817B973902A81C5F7C4AD1A3DDDD5C57FE16B15F841CA075FC05D19872D1BC0CCD5E69690F76955";
    private static final String COMP_PUB_KEY_ODD = "0375C05A9371F2CED4573FB2CFD10A36C00294F34582BCBA257817B973902A81C5";

    private final static String PUB_KEY_EVEN
            = "04C1BE22935ED71A406E2B1B3E5F163582E016FC58E7E676B0FDADD215457EAD67C03BFFC35CA94FCF6011E27B46A7A12C6530C56D454D073E6903AAEE1DEF567C";
    private static final String COMP_PUB_KEY_EVEN = "02C1BE22935ED71A406E2B1B3E5F163582E016FC58E7E676B0FDADD215457EAD67";

    @Test
    public void testToUncompPubKey() {
        testToUncompPubKey(toBytes(PUB_KEY_ODD), toBytes(COMP_PUB_KEY_ODD));
        testToUncompPubKey(toBytes(PUB_KEY_EVEN), toBytes(COMP_PUB_KEY_EVEN));
    }

    private void testToUncompPubKey(byte[] expectedPubKey, byte[] compPubKey) {
        byte[] uncompPubKey = NativeCrypto.nativeCrypto().toUncompPubKey(compPubKey);
        Assertions.assertArrayEquals(expectedPubKey, uncompPubKey);
    }

    @Test
    public void testToUncompPubKeyParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testToUncompPubKey();
            return null;
        });
    }

    @Test
    public void testToUncompPubKeySerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testToUncompPubKey();
            return null;
        });
    }

    @Test
    public void testGenKeyPair() {
        try (NativeSM2 sm2 = new NativeSM2()) {
            byte[] keyPair = sm2.genKeyPair();
            Assertions.assertEquals(SM2_PRIKEY_LEN + SM2_PUBKEY_LEN, keyPair.length);
        }
    }

    @Test
    public void testGenKeyPairParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testGenKeyPair();
            return null;
        });
    }

    @Test
    public void testGenKeyPairSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testGenKeyPair();
            return null;
        });
    }
}
