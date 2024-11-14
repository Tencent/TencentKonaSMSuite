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
import java.security.KeyPair;
import java.security.Security;
import java.util.concurrent.TimeUnit;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;

/**
 * The JMH-based performance test for SM2 decryption.
 */
@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 10)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class SM2CipherPerfTest {

    static {
        TestUtils.addProviders();
        Security.addProvider(new BouncyCastleProvider());
    }

    private final static String PUB_KEY
            = "041D9E2952A06C913BAD21CCC358905ADB3A8097DB6F2F87EB5F393284EC2B7208C30B4D9834D0120216D6F1A73164FDA11A87B0A053F63D992BFB0E4FC1C5D9AD";
    private final static String PRI_KEY
            = "3B03B35C2F26DBC56F6D33677F1B28AF15E45FE9B594A6426BDCAD4A69FF976B";
    private final static KeyPair KEY_PAIR = TestUtils.keyPair(PUB_KEY, PRI_KEY);
    private static final byte[] MESSAGE = TestUtils.dataKB(1);

    @State(Scope.Benchmark)
    public static class EncrypterHolder {

        Cipher encrypter;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            encrypter = Cipher.getInstance("SM2", PROVIDER);
            encrypter.init(Cipher.ENCRYPT_MODE, KEY_PAIR.getPublic());
        }
    }

    @State(Scope.Benchmark)
    public static class EncrypterHolderBC {

        Cipher encrypter;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            encrypter = Cipher.getInstance("SM2", "BC");
            encrypter.init(Cipher.ENCRYPT_MODE, KEY_PAIR.getPublic());
        }
    }

    @State(Scope.Benchmark)
    public static class DecrypterHolder {

        byte[] ciphertext;
        Cipher decrypter;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            ciphertext = ciphertext();
            decrypter = Cipher.getInstance("SM2", PROVIDER);
            decrypter.init(Cipher.DECRYPT_MODE, KEY_PAIR.getPrivate());
        }

        private byte[] ciphertext() throws Exception {
            Cipher cipher = Cipher.getInstance("SM2", PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, KEY_PAIR.getPublic());
            return cipher.doFinal(MESSAGE);
        }
    }

    @State(Scope.Benchmark)
    public static class DecrypterHolderBC {

        byte[] ciphertext;
        Cipher decrypter;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            ciphertext = ciphertext();
            decrypter = Cipher.getInstance("SM2", "BC");
            decrypter.init(Cipher.DECRYPT_MODE, KEY_PAIR.getPrivate());
        }

        private byte[] ciphertext() throws Exception {
            Cipher cipher = Cipher.getInstance("SM2", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, KEY_PAIR.getPublic());
            return cipher.doFinal(MESSAGE);
        }
    }

    @Benchmark
    public byte[] encrypt(EncrypterHolder holder) throws Exception {
        return holder.encrypter.doFinal(MESSAGE);
    }

    @Benchmark
    public byte[] encryptBC(EncrypterHolderBC holder) throws Exception {
        return holder.encrypter.doFinal(MESSAGE);
    }

    @Benchmark
    public byte[] decrypt(DecrypterHolder holder) throws Exception {
        return holder.decrypter.doFinal(holder.ciphertext);
    }

    @Benchmark
    public byte[] decryptBC(DecrypterHolderBC holder) throws Exception {
        return holder.decrypter.doFinal(holder.ciphertext);
    }
}
