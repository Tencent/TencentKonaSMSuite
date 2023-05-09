package com.tencent.kona.crypto.perf;

import com.tencent.kona.crypto.TestUtils;
import com.tencent.kona.crypto.provider.SM3Engine;
import org.bouncycastle.crypto.digests.SM3Digest;
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

import java.util.concurrent.TimeUnit;

/**
 * The JMH-based performance test for SM3 engine.
 */
@Warmup(iterations = 5, time = 5)
@Measurement(iterations = 5, time = 10)
@Fork(value = 2, jvmArgsAppend = {"-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC"})
@Threads(1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class SM3EnginePerfTest {

    private final static byte[] MESSAGE = TestUtils.dataMB(1);

    @State(Scope.Benchmark)
    public static class EngineHolder {

        SM3Engine engine;
        byte[] digest = new byte[32];

        @Setup(Level.Trial)
        public void setup() throws Exception {
            engine = new SM3Engine();
        }
    }

    @State(Scope.Benchmark)
    public static class EngineHolderBC {

        SM3Digest engine;
        byte[] digest = new byte[32];

        @Setup(Level.Trial)
        public void setup() throws Exception {
            engine = new SM3Digest();
        }
    }

    @Benchmark
    public byte[] digest(EngineHolder holder) {
        holder.engine.update(MESSAGE, 0, MESSAGE.length);
        holder.engine.doFinal(holder.digest, 0);
        return holder.digest;
    }

    @Benchmark
    public byte[] digestBC(EngineHolderBC holder) {
        holder.engine.update(MESSAGE, 0, MESSAGE.length);
        holder.engine.doFinal(holder.digest, 0);
        return holder.digest;
    }
}
