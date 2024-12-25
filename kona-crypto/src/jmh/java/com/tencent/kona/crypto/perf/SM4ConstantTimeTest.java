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
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.concurrent.TimeUnit;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The JMH-based performance test for checking constant-time issue.
 */
@Warmup(iterations = 3, time = 5)
@Measurement(iterations = 3, time = 5)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class SM4ConstantTimeTest {

    private static final byte[] KEY_SMALL = toBytes("00000000000000000000000000000000");
    private static final byte[] KEY_MID = toBytes("ffffffff00000000ffffffff00000000");
    private static final byte[] KEY_BIG = toBytes("ffffffffffffffffffffffffffffffff");

    private static final byte[] MESG_SMALL = TestUtils.dataKB(1);
    private static final byte[] MESG_MID = TestUtils.dataKB(512);
    private static final byte[] MESG_BIG = TestUtils.dataKB(1024);

    static {
        TestUtils.addProviders();
    }

    @State(Scope.Benchmark)
    public static class CipherHolder {

        @Param({"KonaCrypto", "KonaCrypto-Native"})
        String provider;

        @Param({"Small", "Mid", "Big"})
        String keyType;

        Cipher cipher;

        @Param({"Small", "Mid", "Big"})
        String dataType;

        byte[] data;

        @Setup(Level.Invocation)
        public void setup() throws Exception {
            byte[] key = null;
            switch (keyType) {
                case "Small":
                    key = KEY_SMALL;
                    break;
                case "Mid":
                    key = KEY_MID;
                    break;
                case "Big":
                    key = KEY_BIG;
            }

            cipher = Cipher.getInstance("SM4/ECB/NoPadding", provider);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "SM4"));

            data = data(dataType);
        }
    }

    private static byte[] data(String dataType) {
        switch (dataType) {
            case "Small": return MESG_SMALL;
            case "Mid": return MESG_MID;
            case "Big": return MESG_BIG;
            default: throw new IllegalArgumentException(
                    "Unsupported data type: " + dataType);
        }
    }

    @Benchmark
    public byte[] encrypt(CipherHolder holder) throws Exception {
        return holder.cipher.doFinal(holder.data);
    }
}
