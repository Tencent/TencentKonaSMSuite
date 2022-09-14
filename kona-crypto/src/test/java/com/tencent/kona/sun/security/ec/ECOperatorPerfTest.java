package com.tencent.kona.sun.security.ec;

import com.tencent.kona.crypto.CryptoUtils;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

import java.math.BigInteger;
import java.security.spec.ECPoint;
import java.util.concurrent.TimeUnit;

/**
 * The JMH-based performance test for EC operations.
 */
@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 10, time = 5)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class ECOperatorPerfTest {

    private static final ECOperator OPERATOR = ECOperator.SM2;

    private static final BigInteger PRIV_KEY = CryptoUtils.toBigInt(
            "00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000");

    @Benchmark
    public ECPoint multiple() {
        return OPERATOR.multiply(PRIV_KEY);
    }
}
