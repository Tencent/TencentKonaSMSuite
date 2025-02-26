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
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.TimeUnit;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;

@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 5)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class KonaECDSASignaturePerfTest {

    static {
        TestUtils.addProviders();
    }

    private final static byte[] SMALL_DATA = TestUtils.data(128);
    private final static byte[] MEDIUM_DATA = TestUtils.dataKB(1);
    private final static byte[] BIG_DATA = TestUtils.dataMB(1);

    @State(Scope.Benchmark)
    public static class SignerHolder {

        @Param({"SunEC", "KonaCrypto-Native", "KonaCrypto-NativeOneShot"})
        String provider;

        @Param({"SHA1", "SHA256", "SHA384", "SHA512"})
        String md;

        @Param({"secp256r1", "secp384r1", "secp521r1"})
        String curve;

        @Param({"Sml", "Mid", "Big"})
        String dataType;

        String sigAlgo;
        KeyPair keyPair;
        byte[] data;
        Signature signer;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            sigAlgo = md + "withECDSA";
            keyPair = keyPair(curve);
            data = data(dataType);

            signer = Signature.getInstance(sigAlgo, provider);
            signer.initSign(keyPair.getPrivate());
        }
    }

    @State(Scope.Benchmark)
    public static class VerifierHolder {

        @Param({"SunEC", "KonaCrypto-Native", "KonaCrypto-NativeOneShot"})
        String provider;

        @Param({"SHA1", "SHA256", "SHA384", "SHA512"})
        String md;

        @Param({"secp256r1", "secp384r1", "secp521r1"})
        String curve;

        @Param({"Sml", "Mid", "Big"})
        String dataType;

        String sigAlgo;
        KeyPair keyPair;
        byte[] data;
        byte[] signature;
        Signature verifier;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            sigAlgo = md + "withECDSA";
            keyPair = keyPair(curve);
            data = data(dataType);
            signature = signature();

            verifier = Signature.getInstance(sigAlgo, provider);
            verifier.initVerify(keyPair.getPublic());
        }

        private byte[] signature() throws Exception {
            Signature signer = Signature.getInstance(sigAlgo, provider);
            signer.initSign(keyPair.getPrivate());
            signer.update(data);
            return signer.sign();
        }
    }

    private static byte[] data(String dataType) {
        switch (dataType) {
            case "Sml": return SMALL_DATA;
            case "Mid": return MEDIUM_DATA;
            case "Big": return BIG_DATA;
            default: throw new IllegalArgumentException(
                    "Unsupported data type: " + dataType);
        }
    }

    @Benchmark
    public byte[] sign(SignerHolder holder) throws Exception {
        holder.signer.update(holder.data);
        return holder.signer.sign();
    }

    @Benchmark
    public boolean verify(VerifierHolder holder) throws Exception {
        holder.verifier.update(holder.data);
        return holder.verifier.verify(holder.signature);
    }

    private static KeyPair keyPair(String curve) throws Exception {
        KeyPairGenerator keyPairGen
                = KeyPairGenerator.getInstance("EC", PROVIDER);
        keyPairGen.initialize(new ECGenParameterSpec(curve));
        return keyPairGen.generateKeyPair();
    }
}
