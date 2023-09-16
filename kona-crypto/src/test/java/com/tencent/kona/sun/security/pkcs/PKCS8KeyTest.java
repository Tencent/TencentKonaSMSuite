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

package com.tencent.kona.sun.security.pkcs;

import com.tencent.kona.crypto.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.interfaces.ECPrivateKey;
import java.util.Base64;

/**
 * The test for PKCS8Test.
 */
public class PKCS8KeyTest {

    // MIGHAgEA...
    private static final String PKCS8_V1_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgU4onpbOcBwltaLFa\n" +
            "FwhpenJm891g0o6r+JBWnoSR6kehRANCAASfQ7HahYYaRrh0lSoU1S/5+kcEirnc\n" +
            "HOVnVK2cTZ447fBYrjPCwiLs4KVjt27138/YYMVy+jYTXh7bPUefO+LL";

    // MIGHAgEB...
    private static final String PKCS8_V2_KEY =
            "MIGHAgEBMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgU4onpbOcBwltaLFa\n" +
            "FwhpenJm891g0o6r+JBWnoSR6kehRANCAASfQ7HahYYaRrh0lSoU1S/5+kcEirnc\n" +
            "HOVnVK2cTZ447fBYrjPCwiLs4KVjt27138/YYMVy+jYTXh7bPUefO+LL";

    // MIGHAgEC...
    private static final String PKCS8_V3_KEY =
            "MIGHAgECMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgU4onpbOcBwltaLFa\n" +
            "FwhpenJm891g0o6r+JBWnoSR6kehRANCAASfQ7HahYYaRrh0lSoU1S/5+kcEirnc\n" +
            "HOVnVK2cTZ447fBYrjPCwiLs4KVjt27138/YYMVy+jYTXh7bPUefO+LL";

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testParsePKCS8V2Key() throws Exception {
        byte[] pkcs8V2Key = Base64.getMimeDecoder().decode(PKCS8_V2_KEY);
        ECPrivateKey ecPrivateKey = (ECPrivateKey) PKCS8Key.parseKey(pkcs8V2Key);

        // After encoding, the version is changed from 0x01 to 0x00.
        byte[] encoded = ecPrivateKey.getEncoded();
        byte[] pkcs8V1Key = Base64.getMimeDecoder().decode(PKCS8_V1_KEY);
        Assertions.assertArrayEquals(pkcs8V1Key, encoded);
    }

    @Test
    public void testParsePKCS8VXKey() throws Exception {
        byte[] pkcs8VXKey = Base64.getMimeDecoder().decode(PKCS8_V3_KEY);
        // The version 0x02 is unknown.
        Assertions.assertThrows(IOException.class, () -> PKCS8Key.parseKey(pkcs8VXKey));
    }
}
