package com.tencent.kona.pkix;

import org.openjdk.jmh.runner.RunnerException;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * It is used for calling the specific JHM-based performance benchmark(s).
 */
public class PerfTestCaller {

    public static void main(String[] args) throws RunnerException {
        String time = LocalDateTime.now().format(
                DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        String filename = "PerfTest-" + time + ".jmh";
        String regrex = args != null && args.length > 0 ? args[0] : "PerfTest";
        PerfTestUtils.runBenchmarks(regrex, filename);
    }
}
