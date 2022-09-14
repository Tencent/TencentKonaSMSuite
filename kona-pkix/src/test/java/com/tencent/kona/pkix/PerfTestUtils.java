package com.tencent.kona.pkix;

import com.tencent.kona.crypto.CryptoUtils;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.ChainedOptionsBuilder;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.concurrent.TimeUnit;

/**
 * The utilities for performance test.
 */
public class PerfTestUtils {

    static {
        setJavaClasspath();
    }

    public static Collection<RunResult> runBenchmarks(
            String regex, String filename) throws RunnerException {
        ChainedOptionsBuilder optBuilder = new OptionsBuilder()
                .include(regex)
                .warmupTime(TimeValue.seconds(5))
                .warmupIterations(5)
                .measurementTime(TimeValue.seconds(10))
                .measurementIterations(5)
                .mode(Mode.Throughput)
                .forks(2)
                .threads(1)
                .shouldDoGC(true)
                .shouldFailOnError(true)
                .resultFormat(ResultFormatType.TEXT)
                .result(filename)
                .shouldFailOnError(true)
                .timeUnit(TimeUnit.SECONDS)
                .jvmArgs("-server", "-Xms2048M", "-Xmx2048M", "-XX:+UseG1GC");
        if (CryptoUtils.isJdk11()) {
            optBuilder.jvmArgsAppend(
                    "--add-exports", "java.base/jdk.internal.misc=ALL-UNNAMED");
        } else if (CryptoUtils.isJdk17()) {
            optBuilder.jvmArgsAppend(
                    "--add-exports", "java.base/jdk.internal.access=ALL-UNNAMED");
        }

        return new Runner(optBuilder.build()).run();
    }

    public static Collection<RunResult> runBenchmarks(Class<?> clazz)
            throws RunnerException {
        String className = clazz.getName();
        String time = LocalDateTime.now().format(
                DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        String filename = className + "-" + time + ".jmh";
        return runBenchmarks(className, filename);
    }

    // A workaround for executing JMH via Maven.
    // The command looks like the below:
    // mvn clean test-compile exec:java -Dexec.classpathScope=test \
    //   -Dexec.mainClass=com.tencent.kona.ssl.tlcp.TlcpPerfTest
    private static void setJavaClasspath() {
        URLClassLoader classLoader
                = (URLClassLoader) PerfTestUtils.class.getClassLoader();
        StringBuilder classpath = new StringBuilder();
        for(URL url : classLoader.getURLs()) {
            classpath.append(url.getPath()).append(File.pathSeparator);
        }
        System.setProperty("java.class.path", classpath.toString());
    }
}
