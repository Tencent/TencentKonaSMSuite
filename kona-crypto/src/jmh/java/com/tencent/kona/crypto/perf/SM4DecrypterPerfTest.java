/*
 * Copyright (C) 2022, 2024, THL A29 Limited, a Tencent company. All rights reserved.
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

package com.tencent.kona.crypto.perf;

import com.tencent.kona.crypto.TestUtils;
import com.tencent.kona.crypto.util.Constants;
import org.openjdk.jmh.annotations.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.concurrent.TimeUnit;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The JMH-based performance test for SM4 cipher.
 */
@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 5)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class SM4DecrypterPerfTest {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] IV = toBytes("00000000000000000000000000000000");
    private static final byte[] GCM_IV = toBytes("000000000000000000000000");

    private static final SecretKey SECRET_KEY = new SecretKeySpec(KEY, "SM4");
    private static final IvParameterSpec IV_PARAM_SPEC = new IvParameterSpec(IV);
    private static final GCMParameterSpec GCM_PARAM_SPEC
            = new GCMParameterSpec(Constants.SM4_GCM_TAG_LEN * 8, GCM_IV);

    private final static byte[] SMALL_DATA = TestUtils.data(128);
    private final static byte[] MEDIUM_DATA = TestUtils.dataKB(1);
    private final static byte[] BIG_DATA = TestUtils.dataMB(1);

    static {
        TestUtils.addProviders();
    }

    @State(Scope.Benchmark)
    public static class DecrypterHolder {

        @Param({"KonaCrypto-Native"})
        String provider;

        @Param({"Small", "Mid", "Big"})
        String dataType;

        byte[] data;

        byte[] ciphertextCBCPadding;
        byte[] ciphertextCBCNoPadding;
        byte[] ciphertextCTRNoPadding;
        byte[] ciphertextECBNoPadding;
        byte[] ciphertextGCMNoPadding;

        Cipher decrypterCBCPadding;
        Cipher decrypterCBCNoPadding;
        Cipher decrypterECBNoPadding;
        Cipher decrypterCTRNoPadding;
        Cipher decrypterGCMNoPadding;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            setupCiphertexts();
            setupDecrypters();
        }

        private void setupCiphertexts() throws Exception {
            data = data(dataType);

            Cipher cipher = Cipher.getInstance(
                    "SM4/CBC/PKCS7Padding", provider);
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);
            ciphertextCBCPadding = cipher.doFinal(data);

            cipher = Cipher.getInstance("SM4/CBC/NoPadding", provider);
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);
            ciphertextCBCNoPadding = cipher.doFinal(data);

            cipher = Cipher.getInstance("SM4/ECB/NoPadding", provider);
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY);
            ciphertextECBNoPadding = cipher.doFinal(data);

            cipher = Cipher.getInstance("SM4/CTR/NoPadding", provider);
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);
            ciphertextCTRNoPadding = cipher.doFinal(data);

            cipher = Cipher.getInstance("SM4/GCM/NoPadding", provider);
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, GCM_PARAM_SPEC);
            ciphertextGCMNoPadding = cipher.doFinal(data);
        }

        private void setupDecrypters() throws Exception {
            decrypterCBCPadding = Cipher.getInstance(
                    "SM4/CBC/PKCS7Padding", provider);
            decrypterCBCPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);

            decrypterCBCNoPadding = Cipher.getInstance(
                    "SM4/CBC/NoPadding", provider);
            decrypterCBCNoPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);

            decrypterECBNoPadding = Cipher.getInstance(
                    "SM4/ECB/NoPadding", provider);
            decrypterECBNoPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY);

            decrypterCTRNoPadding = Cipher.getInstance(
                    "SM4/CTR/NoPadding", provider);
            decrypterCTRNoPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);

            decrypterGCMNoPadding = Cipher.getInstance(
                    "SM4/GCM/NoPadding", provider);
        }
    }

    private static byte[] data(String dataType) {
        switch (dataType) {
            case "Small": return SMALL_DATA;
            case "Mid": return MEDIUM_DATA;
            case "Big": return BIG_DATA;
            default: throw new IllegalArgumentException(
                    "Unsupported data type: " + dataType);
        }
    }

    @Benchmark
    public byte[] cbc(DecrypterHolder holder) throws Exception {
        return holder.decrypterCBCNoPadding.doFinal(holder.ciphertextCBCNoPadding);
    }

    @Benchmark
    public byte[] ecb(DecrypterHolder holder) throws Exception {
        return holder.decrypterECBNoPadding.doFinal(holder.ciphertextECBNoPadding);
    }

    @Benchmark
    public byte[] ctr(DecrypterHolder holder) throws Exception {
        return holder.decrypterCTRNoPadding.doFinal(holder.ciphertextCTRNoPadding);
    }

    @Benchmark
    public byte[] gcm(DecrypterHolder holder) throws Exception {
        holder.decrypterGCMNoPadding.init(
                Cipher.DECRYPT_MODE, SECRET_KEY, GCM_PARAM_SPEC);
        return holder.decrypterGCMNoPadding.doFinal(holder.ciphertextGCMNoPadding);
    }
}
