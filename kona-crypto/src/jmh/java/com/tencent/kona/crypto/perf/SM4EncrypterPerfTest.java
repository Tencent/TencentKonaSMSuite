/*
 * Copyright (C) 2022, 2025, Tencent. All rights reserved.
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

import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The JMH-based performance test for SM4 encryption.
 */
@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 5)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class SM4EncrypterPerfTest {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] IV = toBytes("10000000000000000000000000000000");

    private static final SecretKey SECRET_KEY = new SecretKeySpec(KEY, "SM4");
    private static final IvParameterSpec IV_PARAM_SPEC = new IvParameterSpec(IV);

    private final static byte[] SMALL_DATA = TestUtils.data(128);
    private final static byte[] MEDIUM_DATA = TestUtils.dataKB(1);
    private final static byte[] BIG_DATA = TestUtils.dataMB(1);

    static {
        TestUtils.addProviders();
    }

    @State(Scope.Benchmark)
    public static class EncrypterHolder {

        private BigInteger gcmIvValue = BigInteger.ZERO;

        @Param({"KonaCrypto", "KonaCrypto-Native", "KonaCrypto-NativeOneShot"})
        String provider;

        @Param({"Small", "Mid", "Big"})
        String dataType;

        byte[] data;

        Cipher encrypterCBCNoPadding;
        Cipher encrypterCTRNoPadding;
        Cipher encrypterECBNoPadding;
        Cipher encrypterGCMNoPadding;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            data = data(dataType);

            encrypterCBCNoPadding = Cipher.getInstance(
                    "SM4/CBC/NoPadding", provider);
            encrypterCBCNoPadding.init(
                    Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);

            encrypterCTRNoPadding = Cipher.getInstance(
                    "SM4/CTR/NoPadding", provider);
            encrypterCTRNoPadding.init(
                    Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);

            encrypterECBNoPadding = Cipher.getInstance(
                    "SM4/ECB/NoPadding", provider);
            encrypterECBNoPadding.init(
                    Cipher.ENCRYPT_MODE, SECRET_KEY);

            encrypterGCMNoPadding = Cipher.getInstance(
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
    public byte[] cbc(EncrypterHolder holder) throws Exception {
        if ("KonaCrypto-NativeOneShot".equals(holder.provider)) {
            holder.encrypterCBCNoPadding = Cipher.getInstance(
                    "SM4/CBC/NoPadding", holder.provider);
            holder.encrypterCBCNoPadding.init(
                    Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);
        }

        return holder.encrypterCBCNoPadding.doFinal(holder.data);
    }

    @Benchmark
    public byte[] ctr(EncrypterHolder holder) throws Exception {
        if ("KonaCrypto-NativeOneShot".equals(holder.provider)) {
            holder.encrypterCTRNoPadding = Cipher.getInstance(
                    "SM4/CTR/NoPadding", holder.provider);
            holder.encrypterCTRNoPadding.init(
                    Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);
        }

        return holder.encrypterCTRNoPadding.doFinal(holder.data);
    }

    @Benchmark
    public byte[] ecb(EncrypterHolder holder) throws Exception {
        if ("KonaCrypto-NativeOneShot".equals(holder.provider)) {
            holder.encrypterECBNoPadding = Cipher.getInstance(
                    "SM4/ECB/NoPadding", holder.provider);
            holder.encrypterECBNoPadding.init(
                    Cipher.ENCRYPT_MODE, SECRET_KEY);
        }

        return holder.encrypterECBNoPadding.doFinal(holder.data);
    }

    @Benchmark
    public byte[] gcm(EncrypterHolder holder) throws Exception {
        if ("KonaCrypto-NativeOneShot".equals(holder.provider)) {
            holder.encrypterGCMNoPadding = Cipher.getInstance(
                    "SM4/GCM/NoPadding", holder.provider);
        }

        holder.gcmIvValue = holder.gcmIvValue.add(BigInteger.ONE);
        GCMParameterSpec GCM_PARAM_SPEC = new GCMParameterSpec(
                Constants.SM4_GCM_TAG_LEN * 8, toByte12(holder.gcmIvValue));
        holder.encrypterGCMNoPadding.init(
                Cipher.ENCRYPT_MODE, SECRET_KEY, GCM_PARAM_SPEC);
        return holder.encrypterGCMNoPadding.doFinal(holder.data);
    }

    private static byte[] toByte12(BigInteger ivValue) {
        byte[] result = new byte[12];

        byte[] iv = ivValue.toByteArray();
        if (iv.length >= 12) {
            System.arraycopy(iv, iv.length - 12, result, 0, 12);
        } else {
            System.arraycopy(iv, 0, result, 12 - iv.length, iv.length);
        }

        return result;
    }
}
