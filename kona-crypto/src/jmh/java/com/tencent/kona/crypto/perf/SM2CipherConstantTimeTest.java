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
import com.tencent.kona.crypto.provider.SM2PrivateKey;
import com.tencent.kona.crypto.provider.SM2PublicKey;
import com.tencent.kona.crypto.spec.SM2ParameterSpec;
import com.tencent.kona.crypto.util.Constants;
import com.tencent.kona.sun.security.ec.ECOperator;
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
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.concurrent.TimeUnit;

/**
 * The JMH-based performance test for checking constant-time issue.
 */
@Warmup(iterations = 3, time = 5)
@Measurement(iterations = 5, time = 5)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class SM2CipherConstantTimeTest {

    private final static KeyPair KEY_PAIR_SMALL = keyPair(BigInteger.ONE);
    private final static KeyPair KEY_PAIR_MID = keyPair(
            SM2ParameterSpec.ORDER.divide(Constants.TWO).subtract(BigInteger.ONE));
    private final static KeyPair KEY_PAIR_BIG = keyPair(
            SM2ParameterSpec.ORDER.subtract(Constants.TWO));

    private static final byte[] MESG_SMALL = TestUtils.dataKB(1);
    private static final byte[] MESG_MID = TestUtils.dataKB(512);
    private static final byte[] MESG_BIG = TestUtils.dataKB(1024);

    static {
        TestUtils.addProviders();
    }

    private static KeyPair keyPair(BigInteger priKeyValue) {
        SM2PrivateKey priKey = new SM2PrivateKey(priKeyValue);
        SM2PublicKey pubKey = new SM2PublicKey(
                ECOperator.SM2.multiply(priKeyValue));
        return new KeyPair(pubKey, priKey);
    }

    @State(Scope.Thread)
    public static class CipherHolder {

        @Param({"KonaCrypto", "KonaCrypto-Native", "KonaCrypto-NativeOneShot"})
        String provider;

        @Param({"Small", "Mid", "Big"})
        String keyType;

        Cipher cipher;

        @Param({"Small", "Mid", "Big"})
        String dataType;

        byte[] data;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            KeyPair keyPair = null;
            switch (keyType) {
                case "Small": keyPair = KEY_PAIR_SMALL; break;
                case "Mid": keyPair = KEY_PAIR_MID; break;
                case "Big": keyPair = KEY_PAIR_BIG;
            }

            cipher = Cipher.getInstance("SM2", provider);
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

            switch (dataType) {
                case "Small": data = MESG_SMALL; break;
                case "Mid": data = MESG_MID; break;
                case "Big": data = MESG_BIG;
            }
        }
    }

    @Benchmark
    public byte[] encrypt(CipherHolder holder) throws Exception {
        return holder.cipher.doFinal(holder.data);
    }
}
