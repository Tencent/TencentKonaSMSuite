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

package com.tencent.kona.crypto.perf;

import com.tencent.kona.crypto.TestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

import java.security.MessageDigest;
import java.security.Security;
import java.util.concurrent.TimeUnit;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;

/**
 * The JMH-based performance test for SM3 message digest.
 */
@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 10)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class SM3MessageDigestPerfTest {

    private final static byte[] MESSAGE = TestUtils.dataMB(1);

    static {
        TestUtils.addProviders();
        Security.addProvider(new BouncyCastleProvider());
    }

    @State(Scope.Benchmark)
    public static class MessageDigestHolder {

        MessageDigest md;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            md = MessageDigest.getInstance("SM3", PROVIDER);
        }
    }

    @State(Scope.Benchmark)
    public static class MessageDigestHolderBC {

        MessageDigest md;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            md = MessageDigest.getInstance("SM3", "BC");
        }
    }

    @Benchmark
    public byte[] digest(MessageDigestHolder holder) {
        return holder.md.digest(MESSAGE);
    }

    @Benchmark
    public byte[] digestBC(MessageDigestHolderBC holder) {
        return holder.md.digest(MESSAGE);
    }
}
