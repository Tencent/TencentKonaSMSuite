/*
 * Copyright (C) 2025, THL A29 Limited, a Tencent company. All rights reserved.
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

package com.tencent.kona.ssl.tlcp;

import com.tencent.kona.ssl.TestUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

public class TLCPProfTest {

    static {
        TestUtils.addProviders();
    }

    private static final int ITERATIONS = 1_000_000_000;

    public static void main(String[] args) throws Exception {
        List<Callable<Void>> tasks = new ArrayList<>();

        tasks.add(()-> {testEngine(); return null;});
        tasks.add(()-> {testSocket(); return null;});

        execTasksParallelly(tasks);
    }

    private static void testEngine() throws Exception {
        for (int i = 0; i < ITERATIONS; i++) {
            SSLEngineTest test = new SSLEngineTest();
            test.testSSL();
        }
    }

    private static void testSocket() throws Exception {
        for (int i = 0; i < ITERATIONS; i++) {
            SSLSocketTest test = new SSLSocketTest();
            test.testSSL();
        }
    }

    private static void execTasksParallelly(List<Callable<Void>> tasks) throws Exception {
        ExecutorService executorService = Executors.newFixedThreadPool(tasks.size());
        try {
            List<Future<Void>> futures = executorService.invokeAll(tasks);
            futures.forEach(future -> {
                try {
                    future.get();
                } catch (InterruptedException | ExecutionException e) {
                    throw new RuntimeException("Run task failed", e);
                }
            });
        } finally {
            executorService.shutdown();
        }
    }
}
