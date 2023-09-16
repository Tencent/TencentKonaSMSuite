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

package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.TestUtils;
import com.tencent.kona.crypto.util.Constants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.spec.InvalidParameterSpecException;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.CryptoUtils.toHex;

/**
 * The test for the AlgorithmParameters on SM4.
 */
public class SM4ParametersTest {

    private static final byte[] IV = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
    private static final byte[] GCM_IV = "0123456789ab".getBytes(StandardCharsets.UTF_8);
    private static final byte[] ENCODED_PARAMS = toBytes("041030313233343536373839616263646566");
    private static final byte[] GCM_ENCODED_PARAMS = toBytes("3011040c303132333435363738396162020110");

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testEncode() throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("SM4");
        params.init(new IvParameterSpec(IV));
        byte[] encodedParams = params.getEncoded();
        Assertions.assertArrayEquals(ENCODED_PARAMS, encodedParams);

        params = AlgorithmParameters.getInstance("SM4");
        params.init(new GCMParameterSpec(Constants.SM4_GCM_TAG_LEN << 3, GCM_IV));
        encodedParams = params.getEncoded();
        Assertions.assertArrayEquals(GCM_ENCODED_PARAMS, encodedParams);
    }

    @Test
    public void testDecode() throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("SM4");
        params.init(ENCODED_PARAMS);
        IvParameterSpec decodedParams
                = params.getParameterSpec(IvParameterSpec.class);
        Assertions.assertArrayEquals(IV, decodedParams.getIV());

        final AlgorithmParameters gcmParams = AlgorithmParameters.getInstance("SM4");
        gcmParams.init(GCM_ENCODED_PARAMS);
        GCMParameterSpec decodedGcmParams
                = gcmParams.getParameterSpec(GCMParameterSpec.class);
        Assertions.assertArrayEquals(GCM_IV, decodedGcmParams.getIV());
    }

    @Test
    public void testDecodeFailed() throws Exception {
        final AlgorithmParameters params = AlgorithmParameters.getInstance("SM4");
        params.init(GCM_ENCODED_PARAMS);
        Assertions.assertThrows(
                InvalidParameterSpecException.class,
                () -> params.getParameterSpec(IvParameterSpec.class));

        final AlgorithmParameters gcmParams = AlgorithmParameters.getInstance("SM4");
        gcmParams.init(ENCODED_PARAMS);
        Assertions.assertThrows(
                InvalidParameterSpecException.class,
                () -> gcmParams.getParameterSpec(GCMParameterSpec.class));
    }
}
