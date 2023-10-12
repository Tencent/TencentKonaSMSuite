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

import com.tencent.kona.crypto.CryptoUtils;
import com.tencent.kona.crypto.spec.SM2ParameterSpec;
import com.tencent.kona.sun.security.ec.SM2Operations;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
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

import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.util.concurrent.TimeUnit;

/**
 * The JMH-based performance test for EC operations.
 */
@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 10)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class ECOperatorPerfTest {

    private static final SM2ParameterSpec SM2SPEC = SM2ParameterSpec.instance();
    private static final ECPoint GENERATOR = SM2SPEC.getGenerator();

    private final static byte[] PRIV_KEY = CryptoUtils.toBytes(
            "00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000");
    private static final BigInteger PRIV_KEY_BIG_INT = CryptoUtils.toBigInt(PRIV_KEY);

    @State(Scope.Benchmark)
    public static class OperatorHolderBC {

        FixedPointCombMultiplier multiplier;
        org.bouncycastle.math.ec.ECPoint generator;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            multiplier = new FixedPointCombMultiplier();

            SM2P256V1Curve curve = new SM2P256V1Curve();
            generator = curve.createPoint(GENERATOR.getAffineX(), GENERATOR.getAffineY());

        }
    }

    @Benchmark
    public Object multiple() {
        return SM2Operations.SM2OPS.multiply(GENERATOR, PRIV_KEY);
    }

    @Benchmark
    public Object multipleBC(OperatorHolderBC holder) {
        return holder.multiplier.multiply(holder.generator, PRIV_KEY_BIG_INT);
    }
}
