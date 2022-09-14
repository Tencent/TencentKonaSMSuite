package com.tencent.kona.crypto.perf;

import com.tencent.kona.crypto.provider.SM4Engine;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

import java.util.concurrent.TimeUnit;

/**
 * The JMH-based performance test for SM4 engine.
 */
@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 10)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class SM4EnginePerfTest {

    private static final byte[] KEY = {
            (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
            (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
            (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98,
            (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10
    };

    private static final byte[] DATA = {
            (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
            (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
            (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98,
            (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10
    };

    private static final int[] ROUND_KEY = SM4Engine.expandKey(KEY, true);

    @Benchmark
    public int[] expandKey() {
        int[] roundKey = null;
        for (int i = 1; i < 10000; i++) {
            roundKey = SM4Engine.expandKey(KEY, true);
        }
        return roundKey;
    }

    @Benchmark
    public byte[] processBlock() {
        byte[] ciphertext = new byte[16];
        SM4Engine.processBlock(ROUND_KEY, DATA, 0, ciphertext, 0);
        for (int i = 1; i < 10000; i++) {
            SM4Engine.processBlock(ROUND_KEY, ciphertext, 0, ciphertext, 0);
        }
        return ciphertext;
    }
}
