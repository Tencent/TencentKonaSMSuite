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

package com.tencent.kona.sun.security.util;

import com.tencent.kona.sun.security.x509.AlgorithmId;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;

/**
 * The test for Oid creation.
 */
public class OidTest {

    @Test
    public void testCreateOidWithStr() throws Exception {
        checkCreateOidWithStr(AlgorithmId.EC_oid);
        checkCreateOidWithStr(AlgorithmId.RSAEncryption_oid);
        checkCreateOidWithStr(AlgorithmId.EC_oid);
        checkCreateOidWithStr(AlgorithmId.DSA_oid);
        checkCreateOidWithStr(AlgorithmId.RSASSA_PSS_oid);
        checkCreateOidWithStr(AlgorithmId.SHA256_oid);
        checkCreateOidWithStr(AlgorithmId.SHA384_oid);
        checkCreateOidWithStr(AlgorithmId.SHA512_oid);
        checkCreateOidWithStr(AlgorithmId.SHA256withECDSA_oid);
        checkCreateOidWithStr(AlgorithmId.SM2_OID);
        checkCreateOidWithStr(AlgorithmId.SM3_OID);
        checkCreateOidWithStr(AlgorithmId.SM3withSM2_OID);
    }

    private void checkCreateOidWithStr(ObjectIdentifier expectedOid)
            throws IOException {
        ObjectIdentifier oid = Oid.of(expectedOid.toString());
        Assertions.assertEquals(expectedOid, oid);
    }

    @Test
    public void testCreateOidWithIntArray() throws Exception {
        checkCreateOidWithIntArray(AlgorithmId.EC_oid);
        checkCreateOidWithIntArray(AlgorithmId.RSAEncryption_oid);
        checkCreateOidWithIntArray(AlgorithmId.EC_oid);
        checkCreateOidWithIntArray(AlgorithmId.DSA_oid);
        checkCreateOidWithIntArray(AlgorithmId.RSASSA_PSS_oid);
        checkCreateOidWithIntArray(AlgorithmId.SHA256_oid);
        checkCreateOidWithIntArray(AlgorithmId.SHA384_oid);
        checkCreateOidWithIntArray(AlgorithmId.SHA512_oid);
        checkCreateOidWithIntArray(AlgorithmId.SHA256withECDSA_oid);
        checkCreateOidWithIntArray(AlgorithmId.SM2_OID);
        checkCreateOidWithIntArray(AlgorithmId.SM3_OID);
        checkCreateOidWithIntArray(AlgorithmId.SM3withSM2_OID);
    }

    private void checkCreateOidWithIntArray(ObjectIdentifier expectedOid)
            throws IOException {
        String oidStr = expectedOid.toString();
        String[] parts = oidStr.split("\\.");
        int[] ints = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            ints[i] = Integer.parseInt(parts[i]);
        }
        ObjectIdentifier oid = Oid.of(ints);
        Assertions.assertEquals(expectedOid, oid);
    }

    private void checkCreateOidWithStr(String oidStr) throws IOException {
        ObjectIdentifier oid = Oid.of(oidStr);
        Assertions.assertEquals(oidStr, oid.toString());
    }

    private void checkCreateOidWithIntArray(String oidStr) {
        String[] parts = oidStr.split("\\.");
        int[] intArray = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            intArray[i] = Integer.parseInt(parts[i]);
        }
        ObjectIdentifier oid = Oid.of(intArray);
        Assertions.assertEquals(oidStr, oid.toString());
    }
}
