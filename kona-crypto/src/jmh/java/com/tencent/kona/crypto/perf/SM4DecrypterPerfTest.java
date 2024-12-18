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
import com.tencent.kona.crypto.util.Constants;
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

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.Security;
import java.util.concurrent.TimeUnit;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The JMH-based performance test for SM4 cipher.
 */
@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 10)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class SM4DecrypterPerfTest {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] IV = toBytes("00000000000000000000000000000000");
    private static final byte[] GCM_IV = toBytes("000000000000000000000000");

    private static final SecretKey SECRET_KEY = new SecretKeySpec(KEY, "SM4");
    private static final IvParameterSpec IV_PARAM_SPEC = new IvParameterSpec(IV);
    private static final GCMParameterSpec GCM_PARAM_SPEC
            = new GCMParameterSpec(Constants.SM4_GCM_TAG_LEN * 8, GCM_IV);

    private final static byte[] MESSAGE = TestUtils.dataMB(1);

    static {
        TestUtils.addProviders();
        Security.addProvider(new BouncyCastleProvider());
    }

    @State(Scope.Benchmark)
    public static class DecrypterHolder {

        byte[] ciphertextCBCPadding;
        byte[] ciphertextCBCNoPadding;
        byte[] ciphertextCTRNoPadding;
        byte[] ciphertextECBNoPadding;
        byte[] ciphertextGCMNoPadding;

        Cipher decrypterCBCPadding;
        Cipher decrypterCBCNoPadding;
        Cipher decrypterECBNoPadding;
        Cipher decrypterCTRNoPadding;
        Cipher decrypterGCMNoPadding;

        @Setup(Level.Invocation)
        public void setup() throws Exception {
            setupCiphertexts();
            setupDecrypters();
        }

        private void setupCiphertexts() throws Exception {
            Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", "KonaCrypto");
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);
            ciphertextCBCPadding = cipher.doFinal(MESSAGE);

            cipher = Cipher.getInstance("SM4/CBC/NoPadding", "KonaCrypto");
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);
            ciphertextCBCNoPadding = cipher.doFinal(MESSAGE);

            cipher = Cipher.getInstance("SM4/ECB/NoPadding", "KonaCrypto");
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY);
            ciphertextECBNoPadding = cipher.doFinal(MESSAGE);

            cipher = Cipher.getInstance("SM4/CTR/NoPadding", "KonaCrypto");
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);
            ciphertextCTRNoPadding = cipher.doFinal(MESSAGE);

            cipher = Cipher.getInstance("SM4/GCM/NoPadding", "KonaCrypto");
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, GCM_PARAM_SPEC);
            ciphertextGCMNoPadding = cipher.doFinal(MESSAGE);
        }

        private void setupDecrypters() throws Exception {
            decrypterCBCPadding = Cipher.getInstance(
                    "SM4/CBC/PKCS7Padding", "KonaCrypto");
            decrypterCBCPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);

            decrypterCBCNoPadding = Cipher.getInstance(
                    "SM4/CBC/NoPadding", "KonaCrypto");
            decrypterCBCNoPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);

            decrypterECBNoPadding = Cipher.getInstance(
                    "SM4/ECB/NoPadding", "KonaCrypto");
            decrypterECBNoPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY);

            decrypterCTRNoPadding = Cipher.getInstance(
                    "SM4/CTR/NoPadding", "KonaCrypto");
            decrypterCTRNoPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);

            decrypterGCMNoPadding = Cipher.getInstance(
                    "SM4/GCM/NoPadding", "KonaCrypto");
            decrypterGCMNoPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY, GCM_PARAM_SPEC);
        }
    }

    @State(Scope.Benchmark)
    public static class DecrypterHolderNative {

        byte[] ciphertextCBCPadding;
        byte[] ciphertextCBCNoPadding;
        byte[] ciphertextCTRNoPadding;
        byte[] ciphertextECBNoPadding;
        byte[] ciphertextGCMNoPadding;

        Cipher decrypterCBCPadding;
        Cipher decrypterCBCNoPadding;
        Cipher decrypterECBNoPadding;
        Cipher decrypterCTRNoPadding;
        Cipher decrypterGCMNoPadding;

        @Setup(Level.Invocation)
        public void setup() throws Exception {
            setupCiphertexts();
            setupDecrypters();
        }

        private void setupCiphertexts() throws Exception {
            Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", "KonaCrypto-Native");
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);
            ciphertextCBCPadding = cipher.doFinal(MESSAGE);

            cipher = Cipher.getInstance("SM4/CBC/NoPadding", "KonaCrypto-Native");
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);
            ciphertextCBCNoPadding = cipher.doFinal(MESSAGE);

            cipher = Cipher.getInstance("SM4/ECB/NoPadding", "KonaCrypto-Native");
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY);
            ciphertextECBNoPadding = cipher.doFinal(MESSAGE);

            cipher = Cipher.getInstance("SM4/CTR/NoPadding", "KonaCrypto-Native");
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);
            ciphertextCTRNoPadding = cipher.doFinal(MESSAGE);

            cipher = Cipher.getInstance("SM4/GCM/NoPadding", "KonaCrypto-Native");
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, GCM_PARAM_SPEC);
            ciphertextGCMNoPadding = cipher.doFinal(MESSAGE);
        }

        private void setupDecrypters() throws Exception {
            decrypterCBCPadding = Cipher.getInstance(
                    "SM4/CBC/PKCS7Padding", "KonaCrypto-Native");
            decrypterCBCPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);

            decrypterCBCNoPadding = Cipher.getInstance(
                    "SM4/CBC/NoPadding", "KonaCrypto-Native");
            decrypterCBCNoPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);

            decrypterECBNoPadding = Cipher.getInstance(
                    "SM4/ECB/NoPadding", "KonaCrypto-Native");
            decrypterECBNoPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY);

            decrypterCTRNoPadding = Cipher.getInstance(
                    "SM4/CTR/NoPadding", "KonaCrypto-Native");
            decrypterCTRNoPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);

            decrypterGCMNoPadding = Cipher.getInstance(
                    "SM4/GCM/NoPadding", "KonaCrypto-Native");
            decrypterGCMNoPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY, GCM_PARAM_SPEC);
        }
    }

    @State(Scope.Benchmark)
    public static class DecrypterHolderBC {

        byte[] ciphertextCBCPadding;
        byte[] ciphertextCBCNoPadding;
        byte[] ciphertextECBNoPadding;
        byte[] ciphertextCTRNoPadding;
        byte[] ciphertextGCMNoPadding;

        Cipher decrypterCBCPadding;
        Cipher decrypterCBCNoPadding;
        Cipher decrypterECBNoPadding;
        Cipher decrypterCTRNoPadding;
        Cipher decrypterGCMNoPadding;

        @Setup(Level.Invocation)
        public void setup() throws Exception {
            setupCiphertexts();
            setupDecrypters();
        }

        private void setupCiphertexts() throws Exception {
            Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);
            ciphertextCBCPadding = cipher.doFinal(MESSAGE);

            cipher = Cipher.getInstance("SM4/CBC/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);
            ciphertextCBCNoPadding = cipher.doFinal(MESSAGE);

            cipher = Cipher.getInstance("SM4/ECB/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY);
            ciphertextECBNoPadding = cipher.doFinal(MESSAGE);

            cipher = Cipher.getInstance("SM4/CTR/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);
            ciphertextCTRNoPadding = cipher.doFinal(MESSAGE);

            cipher = Cipher.getInstance("SM4/GCM/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, SECRET_KEY, GCM_PARAM_SPEC);
            ciphertextGCMNoPadding = cipher.doFinal(MESSAGE);
        }

        private void setupDecrypters() throws Exception {
            decrypterCBCPadding = Cipher.getInstance(
                    "SM4/CBC/PKCS7Padding", "BC");
            decrypterCBCPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);

            decrypterCBCNoPadding = Cipher.getInstance(
                    "SM4/CBC/NoPadding", "BC");
            decrypterCBCNoPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);

            decrypterECBNoPadding = Cipher.getInstance(
                    "SM4/ECB/NoPadding", "BC");
            decrypterECBNoPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY);

            decrypterCTRNoPadding = Cipher.getInstance(
                    "SM4/CTR/NoPadding", "BC");
            decrypterCTRNoPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);

            decrypterGCMNoPadding = Cipher.getInstance(
                    "SM4/GCM/NoPadding", "BC");
            decrypterGCMNoPadding.init(
                    Cipher.DECRYPT_MODE, SECRET_KEY, GCM_PARAM_SPEC);
        }
    }

    @Benchmark
    public byte[] cbcPadding(DecrypterHolder holder) throws Exception {
        return holder.decrypterCBCPadding.doFinal(holder.ciphertextCBCPadding);
    }

    @Benchmark
    public byte[] cbcPaddingBC(DecrypterHolderBC holder) throws Exception {
        return holder.decrypterCBCPadding.doFinal(holder.ciphertextCBCPadding);
    }

    @Benchmark
    public byte[] cbcNoPadding(DecrypterHolder holder) throws Exception {
        return holder.decrypterCBCNoPadding.doFinal(holder.ciphertextCBCNoPadding);
    }

    @Benchmark
    public byte[] cbcNoPaddingBC(DecrypterHolderBC holder) throws Exception {
        return holder.decrypterCBCNoPadding.doFinal(holder.ciphertextCBCNoPadding);
    }

    @Benchmark
    public byte[] ecb(DecrypterHolder holder) throws Exception {
        return holder.decrypterECBNoPadding.doFinal(holder.ciphertextECBNoPadding);
    }

    @Benchmark
    public byte[] ecbBC(DecrypterHolderBC holder) throws Exception {
        return holder.decrypterECBNoPadding.doFinal(holder.ciphertextECBNoPadding);
    }

    @Benchmark
    public byte[] ctr(DecrypterHolder holder) throws Exception {
        return holder.decrypterCTRNoPadding.doFinal(holder.ciphertextCTRNoPadding);
    }

    @Benchmark
    public byte[] ctrBC(DecrypterHolderBC holder) throws Exception {
        return holder.decrypterCTRNoPadding.doFinal(holder.ciphertextCTRNoPadding);
    }

    @Benchmark
    public byte[] gcm(DecrypterHolder holder) throws Exception {
        return holder.decrypterGCMNoPadding.doFinal(holder.ciphertextGCMNoPadding);
    }

    @Benchmark
    public byte[] gcmBC(DecrypterHolderBC holder) throws Exception {
        return holder.decrypterGCMNoPadding.doFinal(holder.ciphertextGCMNoPadding);
    }
}
