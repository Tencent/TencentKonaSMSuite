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

package com.tencent.kona.sun.security.ec;

import com.tencent.kona.crypto.TestUtils;
import com.tencent.kona.crypto.spec.SM2ParameterSpec;
import com.tencent.kona.sun.security.util.ArrayUtil;
import com.tencent.kona.sun.security.util.ECUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.spec.ECPoint;
import java.util.Base64;

import static com.tencent.kona.crypto.CryptoUtils.toBigInt;
import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The test for RFC5915Key.
 */
public class RFC5915KeyTest {

    private static final String RFC5915_KEY =
            "MHcCAQEEINAwndUYWVaX1N9MRoYmn+5f+Wvl7EmOz6yHnRkHsWPFoAoGCCqBHM9V\n" +
            "AYItoUQDQgAEEd8Dsf32cEr/jHWYN8EgGHCFh5qu8AyTpdscNUvtx5H1D1mW8kJa\n" +
            "lvIpfGjy54xSg5RS6taPjDKqfEK89CJUqQ==";

    private static final byte[] S = toBytes(
            "d0309dd518595697d4df4c4686269fee5ff96be5ec498ecfac879d1907b163c5");

    private static final byte[] ENCODED_KEY
            = Base64.getMimeDecoder().decode(RFC5915_KEY);

    private static final byte[] ENCODED_KEY_WITHOUT_PUB_KEY = toBytes(
            "30310201010420d0309dd518595697d4df4c4686269fee5ff96be5ec498ecfac879d1907b163c5a00a06082a811ccf5501822d");

    private static final byte[] PUB_KEY = toBytes(
            "0411df03b1fdf6704aff8c759837c120187085879aaef00c93a5db1c354bedc791f50f5996f2425a96f2297c68f2e78c52839452ead68f8c32aa7c42bcf42254a9");

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testCreateRFC5915KeyWithEncodedKey() throws Exception {
        RFC5915Key key = new RFC5915Key(ENCODED_KEY);

        Assertions.assertEquals(key.getAlgorithm(), "EC");
        Assertions.assertEquals(
                SM2ParameterSpec.instance().getCurve(),
                key.getParams().getCurve());
        Assertions.assertEquals(toBigInt(S), key.getS());
    }

    @Test
    public void testCreateRFC5915KeyWithSAndParams() throws Exception {
        RFC5915Key key = new RFC5915Key(
                toBigInt(S), null, SM2ParameterSpec.instance());

        Assertions.assertEquals(key.getAlgorithm(), "EC");
        Assertions.assertEquals(
                SM2ParameterSpec.instance().getCurve(),
                key.getParams().getCurve());
        Assertions.assertEquals(toBigInt(S), key.getS());
    }

    @Test
    public void testCreateRFC5915KeyWithSArrayLEAndParams() throws Exception {
        // The s must be little-endian
        byte[] sArray = S.clone();
        ArrayUtil.reverse(sArray);
        RFC5915Key key = new RFC5915Key(
                sArray, null, SM2ParameterSpec.instance());
        Assertions.assertEquals(key.getAlgorithm(), "EC");
        Assertions.assertEquals(
                SM2ParameterSpec.instance().getCurve(),
                key.getParams().getCurve());
        Assertions.assertEquals(toBigInt(S), key.getS());
    }

    @Test
    public void testEncodeWithEncodedKey() throws Exception {
        RFC5915Key key = new RFC5915Key(
                Base64.getMimeDecoder().decode(RFC5915_KEY));
        Assertions.assertArrayEquals(ENCODED_KEY, key.getEncoded());
    }

    @Test
    public void testEncodeWithParams() throws Exception {
        ECPoint pubPoint = ECUtil.decodePoint(PUB_KEY, SM2ParameterSpec.CURVE);

        RFC5915Key key = new RFC5915Key(
                toBigInt(S), pubPoint, SM2ParameterSpec.instance());
        Assertions.assertArrayEquals(ENCODED_KEY, key.getEncoded());

        // The s must be little-endian
        byte[] sArray = S.clone();
        ArrayUtil.reverse(sArray);
        key = new RFC5915Key(sArray, pubPoint, SM2ParameterSpec.instance());
        Assertions.assertArrayEquals(ENCODED_KEY, key.getEncoded());
    }

    @Test
    public void testEncodeWithoutParamsNoPubPoint() throws Exception {
        RFC5915Key key = new RFC5915Key(
                toBigInt(S), null, SM2ParameterSpec.instance());
        Assertions.assertArrayEquals(
                ENCODED_KEY_WITHOUT_PUB_KEY, key.getEncoded());

        // The s must be little-endian
        byte[] sArray = S.clone();
        ArrayUtil.reverse(sArray);
        key = new RFC5915Key(sArray, null, SM2ParameterSpec.instance());
        Assertions.assertArrayEquals(
                ENCODED_KEY_WITHOUT_PUB_KEY, key.getEncoded());
    }
}
