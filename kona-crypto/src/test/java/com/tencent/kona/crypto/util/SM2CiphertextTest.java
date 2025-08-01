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

package com.tencent.kona.crypto.util;

import com.tencent.kona.crypto.CryptoUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;

/**
 * The test for SM2Ciphertext.
 */
public class SM2CiphertextTest {

    private static final String DER_C1C3C2
            = "306A"
            + "0221"
            + "008A2A155B9C644A45D118BCC3213325EECDD970307406F1AB90CB1EC0A0445A6E"
            + "0220"
            + "054797A7ABB739E783CFACE5B1184458685148F40D4C0680DA2AEB4538307555"
            + "0420"
            + "16A9E16A16E440A245DD744E7966A32AC49D22152E9F560F7506E9FAFF293D73"
            + "0401"
            + "06";

    private static final String C1_WITHOUT_04
            = "8A2A155B9C644A45D118BCC3213325EECDD970307406F1AB90CB1EC0A0445A6E"
            + "054797A7ABB739E783CFACE5B1184458685148F40D4C0680DA2AEB4538307555"
            + "16A9E16A16E440A245DD744E7966A32AC49D22152E9F560F7506E9FAFF293D73"
            + "06";

    private static SM2Ciphertext sm2Ciphertext;
    private static SM2Ciphertext sm2CiphertextNone;

    @BeforeAll
    public static void setup() throws IOException {
        sm2Ciphertext = SM2Ciphertext.builder()
                .format(SM2Ciphertext.Format.DER_C1C3C2)
                .encodedCiphertext(CryptoUtils.toBytes(DER_C1C3C2))
                .build();

        sm2CiphertextNone = SM2Ciphertext.builder()
                .format(SM2Ciphertext.Format.NONE)
                .coordX(CryptoUtils.toBytes("8A2A155B9C644A45D118BCC3213325EECDD970307406F1AB90CB1EC0A0445A6E"))
                .coordY(CryptoUtils.toBytes("054797A7ABB739E783CFACE5B1184458685148F40D4C0680DA2AEB4538307555"))
                .digest(CryptoUtils.toBytes("16A9E16A16E440A245DD744E7966A32AC49D22152E9F560F7506E9FAFF293D73"))
                .ciphertext(CryptoUtils.toBytes("06"))
                .build();
    }

    @Test
    public void testCheckRawC1C3C2() {
        Assertions.assertThrows(IOException.class, () -> SM2Ciphertext.builder()
                .format(SM2Ciphertext.Format.RAW_C1C3C2)
                .encodedCiphertext(CryptoUtils.toBytes(C1_WITHOUT_04))
                .build());
    }

    @Test
    public void testCheckRawC1C2C3() {
        Assertions.assertThrows(IOException.class, () -> SM2Ciphertext.builder()
                .format(SM2Ciphertext.Format.RAW_C1C2C3)
                .encodedCiphertext(CryptoUtils.toBytes(C1_WITHOUT_04))
                .build());
    }

    @Test
    public void testRawC1C3C2() {
        byte[]  rawC1C3C2 = sm2Ciphertext.rawC1C3C2();
        byte[]  rawC1C3C2None = sm2CiphertextNone.rawC1C3C2();
        byte[] expected = CryptoUtils.toBytes("04"
                + "8A2A155B9C644A45D118BCC3213325EECDD970307406F1AB90CB1EC0A0445A6E"
                + "054797A7ABB739E783CFACE5B1184458685148F40D4C0680DA2AEB4538307555"
                + "16A9E16A16E440A245DD744E7966A32AC49D22152E9F560F7506E9FAFF293D73"
                + "06");
        Assertions.assertArrayEquals(expected, rawC1C3C2);
        Assertions.assertArrayEquals(expected, rawC1C3C2None);
    }

    @Test
    public void testRawC1C2C3() {
        byte[] rawC1C2C3 = sm2Ciphertext.rawC1C2C3();
        byte[] rawC1C2C3None = sm2CiphertextNone.rawC1C2C3();
        byte[] expected = CryptoUtils.toBytes("04"
                + "8A2A155B9C644A45D118BCC3213325EECDD970307406F1AB90CB1EC0A0445A6E"
                + "054797A7ABB739E783CFACE5B1184458685148F40D4C0680DA2AEB4538307555"
                + "06"
                + "16A9E16A16E440A245DD744E7966A32AC49D22152E9F560F7506E9FAFF293D73");
        Assertions.assertArrayEquals(expected, rawC1C2C3);
        Assertions.assertArrayEquals(expected, rawC1C2C3None);
    }

    @Test
    public void testDerC1C3C2() throws IOException {
        byte[]  derC1C3C2 = sm2Ciphertext.derC1C3C2();
        byte[]  derC1C3C2None = sm2CiphertextNone.derC1C3C2();
        Assertions.assertArrayEquals(CryptoUtils.toBytes(DER_C1C3C2), derC1C3C2);
        Assertions.assertArrayEquals(CryptoUtils.toBytes(DER_C1C3C2), derC1C3C2None);
    }

    @Test
    public void testDerC1C2C3() throws IOException {
        byte[]  derC1C2C3 = sm2Ciphertext.derC1C2C3();
        byte[]  derC1C2C3None = sm2CiphertextNone.derC1C2C3();
        byte[] expected = CryptoUtils.toBytes("306A"
                + "0221"
                + "008A2A155B9C644A45D118BCC3213325EECDD970307406F1AB90CB1EC0A0445A6E"
                + "0220"
                + "054797A7ABB739E783CFACE5B1184458685148F40D4C0680DA2AEB4538307555"
                + "0401"
                + "06"
                + "0420"
                + "16A9E16A16E440A245DD744E7966A32AC49D22152E9F560F7506E9FAFF293D73");
        Assertions.assertArrayEquals(expected, derC1C2C3);
        Assertions.assertArrayEquals(expected, derC1C2C3None);
    }
}
