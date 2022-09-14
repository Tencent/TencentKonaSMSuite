package com.tencent.kona.crypto.perf;

import com.tencent.kona.crypto.TestUtils;
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
import java.security.KeyPairGenerator;
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

    private static final byte[] MESSAGE = TestUtils.dataKB(1);

    static {
        TestUtils.addProviders();
    }

    @State(Scope.Benchmark)
    public static class EncrypterHolder {

        Cipher encrypter;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            encrypter = Cipher.getInstance("SM2", PROVIDER);
            encrypter.init(Cipher.ENCRYPT_MODE, keyPair().getPublic());
        }

        private KeyPair keyPair() throws Exception {
            KeyPairGenerator keyPairGenerator
                    = KeyPairGenerator.getInstance("SM2", PROVIDER);
            return keyPairGenerator.generateKeyPair();
        }
    }

    @State(Scope.Benchmark)
    public static class DecrypterHolder {

        byte[] ciphertext;
        Cipher decrypter;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            KeyPair keyPair = keyPair();
            ciphertext = ciphertext(keyPair);

            decrypter = Cipher.getInstance("SM2", PROVIDER);
            decrypter.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        }

        private KeyPair keyPair() throws Exception {
            KeyPairGenerator keyPairGenerator
                    = KeyPairGenerator.getInstance("SM2", PROVIDER);
            return keyPairGenerator.generateKeyPair();
        }

        private byte[] ciphertext(KeyPair keyPair) throws Exception {
            Cipher cipher = Cipher.getInstance("SM2", PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            return cipher.doFinal(MESSAGE);
        }
    }

    @Benchmark
    public byte[] encrypt(EncrypterHolder holder) throws Exception {
        return holder.encrypter.doFinal(MESSAGE);
    }

    @Benchmark
    public byte[] decrypt(DecrypterHolder holder) throws Exception {
        return holder.decrypter.doFinal(holder.ciphertext);
    }
}
