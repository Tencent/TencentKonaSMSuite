package com.tencent.kona.crypto.perf;

import com.tencent.kona.crypto.TestUtils;
import com.tencent.kona.crypto.util.Constants;
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

import java.util.concurrent.TimeUnit;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The JMH-based performance test for SM4 encryption.
 */
@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 10)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class SM4EncrypterPerfTest {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] IV = toBytes("00000000000000000000000000000000");
    private static final byte[] GCM_IV = toBytes("000000000000000000000000");

    private static final SecretKey SECRET_KEY = new SecretKeySpec(KEY, "SM4");
    private static final IvParameterSpec IV_PARAM_SPEC = new IvParameterSpec(IV);
    private static final GCMParameterSpec GCM_PARAM_SPEC
            = new GCMParameterSpec(Constants.SM4_GCM_TAG_LEN * 8, GCM_IV);

    private final static byte[] DATA = TestUtils.dataMB(1);

    static {
        TestUtils.addProviders();
    }

    @State(Scope.Benchmark)
    public static class EncrypterHolder {
        Cipher encrypterCBCPadding;
        Cipher encrypterCBCNoPadding;
        Cipher encrypterCTRNoPadding;
        Cipher encrypterGCMNoPadding;

        @Setup(Level.Invocation)
        public void setup() throws Exception {
            encrypterCBCPadding = Cipher.getInstance(
                    "SM4/CBC/PKCS7Padding", PROVIDER);
            encrypterCBCPadding.init(
                    Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);

            encrypterCBCNoPadding = Cipher.getInstance(
                    "SM4/CBC/NoPadding", PROVIDER);
            encrypterCBCNoPadding.init(
                    Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);

            encrypterCTRNoPadding = Cipher.getInstance(
                    "SM4/CTR/NoPadding", PROVIDER);
            encrypterCTRNoPadding.init(
                    Cipher.ENCRYPT_MODE, SECRET_KEY, IV_PARAM_SPEC);

            encrypterGCMNoPadding = Cipher.getInstance(
                    "SM4/GCM/NoPadding", PROVIDER);
            encrypterGCMNoPadding.init(
                    Cipher.ENCRYPT_MODE, SECRET_KEY, GCM_PARAM_SPEC);
        }
    }

    @Benchmark
    public byte[] cbcPadding(EncrypterHolder holder) throws Exception {
        return holder.encrypterCBCPadding.doFinal(DATA);
    }

    @Benchmark
    public byte[] cbcNoPadding(EncrypterHolder holder) throws Exception {
        return holder.encrypterCBCNoPadding.doFinal(DATA);
    }

    @Benchmark
    public byte[] ctr(EncrypterHolder holder) throws Exception {
        return holder.encrypterCTRNoPadding.doFinal(DATA);
    }

    @Benchmark
    public byte[] gcm(EncrypterHolder holder) throws Exception {
        return holder.encrypterGCMNoPadding.doFinal(DATA);
    }
}
