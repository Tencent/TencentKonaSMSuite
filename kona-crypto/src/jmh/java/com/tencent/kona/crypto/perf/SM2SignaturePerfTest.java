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
import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
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

import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.concurrent.TimeUnit;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The JMH-based performance test for SM2 signature.
 */
@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 10)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class SM2SignaturePerfTest {

    private final static String PUB_KEY
            = "041D9E2952A06C913BAD21CCC358905ADB3A8097DB6F2F87EB5F393284EC2B7208C30B4D9834D0120216D6F1A73164FDA11A87B0A053F63D992BFB0E4FC1C5D9AD";
    private final static String PRI_KEY
            = "3B03B35C2F26DBC56F6D33677F1B28AF15E45FE9B594A6426BDCAD4A69FF976B";
    private final static KeyPair KEY_PAIR = TestUtils.keyPair(PUB_KEY, PRI_KEY);
    private final static byte[] ID = toBytes("01234567");
    private final static byte[] MESSAGE = TestUtils.dataKB(1);

    static {
        TestUtils.addProviders();
        Security.addProvider(new BouncyCastleProvider());
    }

    @State(Scope.Benchmark)
    public static class SignerHolder {

        Signature signer;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            signer = Signature.getInstance("SM2", PROVIDER);
            signer.setParameter(new SM2SignatureParameterSpec(
                    ID, (ECPublicKey) KEY_PAIR.getPublic()));
            signer.initSign(KEY_PAIR.getPrivate());
        }
    }

    @State(Scope.Benchmark)
    public static class SignerHolderBC {

        Signature signer;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            signer = Signature.getInstance(
                    GMObjectIdentifiers.sm2sign_with_sm3.toString(), "BC");
            signer.setParameter(new SM2ParameterSpec(ID));
            signer.initSign(KEY_PAIR.getPrivate());
        }
    }

    @State(Scope.Benchmark)
    public static class VerifierHolder {

        byte[] signature;
        Signature verifier;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            signature = signature();

            verifier = Signature.getInstance("SM2", PROVIDER);
            verifier.setParameter(new SM2SignatureParameterSpec(
                    ID, (ECPublicKey) KEY_PAIR.getPublic()));
            verifier.initVerify(KEY_PAIR.getPublic());
        }

        private byte[] signature() throws Exception {
            Signature signer = Signature.getInstance("SM2", PROVIDER);
            signer.setParameter(new SM2SignatureParameterSpec(
                    ID, (ECPublicKey) KEY_PAIR.getPublic()));
            signer.initSign(KEY_PAIR.getPrivate());
            signer.update(MESSAGE);
            return signer.sign();
        }
    }

    @State(Scope.Benchmark)
    public static class VerifierHolderBC {

        byte[] signature;
        Signature verifier;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            signature = signature();

            verifier = Signature.getInstance(
                    GMObjectIdentifiers.sm2sign_with_sm3.toString(), "BC");
            verifier.setParameter(new SM2ParameterSpec(ID));
            verifier.initVerify(KEY_PAIR.getPublic());
        }

        private byte[] signature() throws Exception {
            Signature signer = Signature.getInstance(
                    GMObjectIdentifiers.sm2sign_with_sm3.toString(), "BC");
            signer.setParameter(new SM2ParameterSpec(ID));
            signer.initSign(KEY_PAIR.getPrivate());
            return signer.sign();
        }
    }

    @Benchmark
    public byte[] sign(SignerHolder holder) throws Exception {
        holder.signer.update(MESSAGE);
        return holder.signer.sign();
    }

    @Benchmark
    public byte[] signBC(SignerHolderBC holder) throws Exception {
        holder.signer.update(MESSAGE);
        return holder.signer.sign();
    }

    @Benchmark
    public boolean verify(VerifierHolder holder) throws Exception {
        holder.verifier.update(MESSAGE);
        return holder.verifier.verify(holder.signature);
    }

    @Benchmark
    public boolean verifyBC(VerifierHolderBC holder) throws Exception {
        holder.verifier.update(MESSAGE);
        return holder.verifier.verify(holder.signature);
    }
}
