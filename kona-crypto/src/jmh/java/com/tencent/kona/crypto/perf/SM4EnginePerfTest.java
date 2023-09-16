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

import com.tencent.kona.crypto.provider.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
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

import java.util.concurrent.TimeUnit;

/**
 * The JMH-based performance test for SM4 engine.
 */
@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 10)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class SM4EnginePerfTest {

    private static final byte[] KEY = {
            (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
            (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
            (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98,
            (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10
    };

    private static final byte[] DATA = {
            (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
            (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
            (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98,
            (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10
    };

    @State(Scope.Benchmark)
    public static class EncrypterHolder {

        SM4Engine engine;

        @Setup(Level.Invocation)
        public void setup() throws Exception {
            engine = new SM4Engine(KEY, true);
        }
    }

    @State(Scope.Benchmark)
    public static class EncrypterHolderBC {

        org.bouncycastle.crypto.engines.SM4Engine engine;

        @Setup(Level.Invocation)
        public void setup() throws Exception {
            engine = new org.bouncycastle.crypto.engines.SM4Engine();
            engine.init(true, new KeyParameter(KEY));
        }
    }

    @Benchmark
    public byte[] processBlock(EncrypterHolder holder) {
        byte[] ciphertext = new byte[16];
        holder.engine.processBlock(DATA, 0, ciphertext, 0);
        for (int i = 1; i < 10000; i++) {
            holder.engine.processBlock(ciphertext, 0, ciphertext, 0);
        }
        return ciphertext;
    }

    @Benchmark
    public byte[] processBlockBC(EncrypterHolderBC holder) {
        byte[] ciphertext = new byte[16];
        holder.engine.processBlock(DATA, 0, ciphertext, 0);
        for (int i = 1; i < 10000; i++) {
            holder.engine.processBlock(ciphertext, 0, ciphertext, 0);
        }
        return ciphertext;
    }
}
