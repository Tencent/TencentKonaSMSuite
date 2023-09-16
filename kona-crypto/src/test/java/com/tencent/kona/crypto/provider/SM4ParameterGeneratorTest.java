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
import com.tencent.kona.sun.security.util.DerInputStream;
import com.tencent.kona.sun.security.util.DerValue;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidParameterException;
import java.security.SecureRandom;

import static com.tencent.kona.crypto.util.Constants.SM4_GCM_IV_LEN;
import static com.tencent.kona.crypto.util.Constants.SM4_IV_LEN;

/**
 * The test for the AlgorithmParameterGenerator on SM4.
 */
public class SM4ParameterGeneratorTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testInit() throws Exception {
        AlgorithmParameterGenerator paramGen
                = AlgorithmParameterGenerator.getInstance("SM4");
        paramGen.init(new SM4GenParameterSpec(IvParameterSpec.class));
        paramGen.init(new SM4GenParameterSpec(GCMParameterSpec.class));
    }

    @Test
    public void testInitFailed() throws Exception {
        AlgorithmParameterGenerator paramGen
                = AlgorithmParameterGenerator.getInstance("SM4");
        Assertions.assertThrows(InvalidParameterException.class,
                () -> paramGen.init(Constants.SM4_IV_LEN));
        Assertions.assertThrows(InvalidParameterException.class,
                () -> paramGen.init(Constants.SM4_GCM_IV_LEN, new SecureRandom()));
    }

    @Test
    public void testGenerateParameters() throws Exception {
        AlgorithmParameterGenerator paramGen
                = AlgorithmParameterGenerator.getInstance("SM4");
        paramGen.init(new SM4GenParameterSpec(IvParameterSpec.class));
        AlgorithmParameters params = paramGen.generateParameters();
        Assertions.assertEquals(SM4_IV_LEN, iv(params.getEncoded()).length);

        AlgorithmParameterGenerator gcmParamGen
                = AlgorithmParameterGenerator.getInstance("SM4");
        gcmParamGen.init(new SM4GenParameterSpec(GCMParameterSpec.class));
        AlgorithmParameters gcmParams = gcmParamGen.generateParameters();
        Assertions.assertEquals(SM4_GCM_IV_LEN,
                gcmDecode(gcmParams.getEncoded()).length);
    }

    private byte[] iv(byte[] encoded) throws IOException {
        DerInputStream der = new DerInputStream(encoded);
        return der.getOctetString();
    }

    private byte[] gcmDecode(byte[] encoded) throws IOException {
        DerValue val = new DerValue(encoded);
        return val.data.getOctetString();
    }
}
