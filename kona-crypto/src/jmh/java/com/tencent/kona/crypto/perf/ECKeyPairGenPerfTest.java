/*
 * Copyright (C) 2025, THL A29 Limited, a Tencent company. All rights reserved.
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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.TimeUnit;

/**
 * The JMH-based performance test for SM2 key pair generation.
 */
@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 5)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class ECKeyPairGenPerfTest {

    static {
        TestUtils.addProviders();
    }

    @State(Scope.Benchmark)
    public static class KeyPairGenHolder {

        @Param({"SunEC", "KonaCrypto-Native", "KonaCrypto-NativeOneShot"})
        String provider;

        @Param({"secp256r1", "secp384r1", "secp521r1"})
        String curve;

        KeyPairGenerator keyPairGenerator;

        @Setup
        public void setup() throws Exception {
            keyPairGenerator = KeyPairGenerator.getInstance("EC", provider);
            keyPairGenerator.initialize(new ECGenParameterSpec(curve));
        }
    }

    @Benchmark
    public KeyPair genKeyPair(KeyPairGenHolder holder) {
        return holder.keyPairGenerator.generateKeyPair();
    }
}
