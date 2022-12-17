package com.tencent.kona.crypto.perf;

import com.tencent.kona.crypto.TestUtils;
import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;
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
import java.security.KeyPairGenerator;
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

    private final static byte[] USER_ID = toBytes("01234567");
    private final static byte[] MESSAGE = TestUtils.dataKB(1);

    static {
        TestUtils.addProviders();
    }

    @State(Scope.Benchmark)
    public static class SignerHolder {

        Signature signer;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            KeyPair keyPair = keyPair();
            signer = Signature.getInstance("SM2", PROVIDER);
            signer.setParameter(new SM2SignatureParameterSpec(
                    USER_ID, (ECPublicKey) keyPair.getPublic()));
            signer.initSign(keyPair.getPrivate());
        }

        private KeyPair keyPair() throws Exception {
            KeyPairGenerator keyPairGenerator
                    = KeyPairGenerator.getInstance("SM2", PROVIDER);
            return keyPairGenerator.generateKeyPair();
        }
    }

    @State(Scope.Benchmark)
    public static class VerifierHolder {

        byte[] signature;
        Signature verifier;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            KeyPair keyPair = keyPair();

            signature = signature(keyPair);

            verifier = Signature.getInstance("SM2", PROVIDER);
            verifier.setParameter(new SM2SignatureParameterSpec(
                    USER_ID, (ECPublicKey) keyPair.getPublic()));
            verifier.initVerify(keyPair.getPublic());
        }

        private KeyPair keyPair() throws Exception {
            KeyPairGenerator keyPairGenerator
                    = KeyPairGenerator.getInstance("SM2", PROVIDER);
            return keyPairGenerator.generateKeyPair();
        }

        private byte[] signature(KeyPair keyPair) throws Exception {
            Signature signer = Signature.getInstance("SM2", PROVIDER);
            signer.setParameter(new SM2SignatureParameterSpec(
                    USER_ID, (ECPublicKey) keyPair.getPublic()));
            signer.initSign(keyPair.getPrivate());
            signer.update(MESSAGE);
            return signer.sign();
        }
    }

    @Benchmark
    public byte[] sign(SignerHolder holder) throws Exception {
        holder.signer.update(MESSAGE);
        return holder.signer.sign();
    }

    @Benchmark
    public boolean verify(VerifierHolder holder) throws Exception {
        holder.verifier.update(MESSAGE);
        return holder.verifier.verify(holder.signature);
    }
}
