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

import com.tencent.kona.crypto.TestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static com.tencent.kona.crypto.util.Constants.SM4_GCM_TAG_LEN;
import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The test for SM4 with BouncyCastle.
 */
public class SM4WithBCTest {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] IV = toBytes("00000000000000000000000000000000");
    private static final byte[] GCM_IV = toBytes("000000000000000000000000");
    private static final byte[] AAD = toBytes("0123456789");

    private static final byte[] MESSAGE = toBytes("0123456789abcdef0123456789abcdef");

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testCipher() throws Exception {
        testCipher("SM4/CBC/NoPadding", new IvParameterSpec(IV));
        testCipher("SM4/CBC/PKCS7Padding", new IvParameterSpec(IV));
        testCipher("SM4/CTR/NoPadding", new IvParameterSpec(IV));
        testCipher("SM4/ECB/NoPadding", null);
        testCipher("SM4/ECB/PKCS7Padding", null);
        testCipher("SM4/GCM/NoPadding", new GCMParameterSpec(SM4_GCM_TAG_LEN * 8, GCM_IV));
    }

    public void testCipher(String algorithm,
            AlgorithmParameterSpec paramSpec) throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "SM4");

        Cipher cipher = Cipher.getInstance(algorithm, PROVIDER);
        Cipher cipherBC = Cipher.getInstance(algorithm, "BC");

        if (paramSpec != null) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
            if (paramSpec instanceof GCMParameterSpec) {
                cipher.updateAAD(AAD);
            }
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        if (paramSpec != null) {
            cipherBC.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
            if (paramSpec instanceof GCMParameterSpec) {
                cipherBC.updateAAD(AAD);
            }
        } else {
            cipherBC.init(Cipher.ENCRYPT_MODE, secretKey);
        }
        byte[] ciphertextBC = cipherBC.doFinal(MESSAGE);

        Assertions.assertArrayEquals(ciphertextBC, ciphertext);

        if (paramSpec != null) {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
            if (paramSpec instanceof GCMParameterSpec) {
                cipher.updateAAD(AAD);
            }
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        }
        byte[] cleartext = cipher.doFinal(ciphertext);

        if (paramSpec != null) {
            cipherBC.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
            if (paramSpec instanceof GCMParameterSpec) {
                cipherBC.updateAAD(AAD);
            }
        } else {
            cipherBC.init(Cipher.DECRYPT_MODE, secretKey);
        }
        byte[] cleartextBC = cipherBC.doFinal(ciphertext);

        Assertions.assertArrayEquals(cleartextBC, cleartext);
    }
}
