/*
 * Copyright (C) 2022, 2025, THL A29 Limited, a Tencent company. All rights reserved.
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
import org.openjdk.jmh.annotations.*;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.util.concurrent.TimeUnit;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The JMH-based performance test for SM3 HMAC.
 */
@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 5)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class SM3HMacPerfTest {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final SecretKey SECRET_KEY = new SecretKeySpec(KEY, "SM4");

    private final static byte[] SMALL_DATA = TestUtils.data(128);
    private final static byte[] MEDIUM_DATA = TestUtils.dataKB(1);
    private final static byte[] BIG_DATA = TestUtils.dataMB(1);

    static {
        TestUtils.addProviders();
    }

    @State(Scope.Benchmark)
    public static class MacHolder {

        @Param({"KonaCrypto", "KonaCrypto-Native", "KonaCrypto-NativeOneShot"})
        String provider;

        @Param({"Small", "Mid", "Big"})
        String dataType;

        byte[] data;
        Mac mac;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            data = data(dataType);

            mac = Mac.getInstance("HmacSM3", provider);
            mac.init(SECRET_KEY);
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
    public byte[] mac(MacHolder holder) throws Exception {
        return holder.mac.doFinal(holder.data);
    }
}
