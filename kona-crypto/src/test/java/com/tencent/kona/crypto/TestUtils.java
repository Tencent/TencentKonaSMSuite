/*
 * Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
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

package com.tencent.kona.crypto;

import com.tencent.kona.crypto.provider.SM2PrivateKey;
import com.tencent.kona.crypto.provider.SM2PublicKey;

import java.security.KeyPair;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The utilities for tests.
 */
public class TestUtils {

    public static final String PROVIDER = CryptoInsts.PROV_NAME;

    public static final byte[] EMPTY = new byte[0];

    public static void addProviders() {
        Security.addProvider(new KonaCryptoProvider());
    }

    public static void repeatTaskParallelly(Callable<Void> task, int count)
            throws Exception {
        List<Callable<Void>> tasks = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            tasks.add(task);
        }

        ExecutorService executorService = Executors.newFixedThreadPool(count);
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

    public static void repeatTaskParallelly(Callable<Void> task)
            throws Exception {
        repeatTaskParallelly(task, 100);
    }

    public static void repeatTaskSerially(Callable<Void> task, int count)
            throws Exception {
        for (int i = 0; i < count; i++) {
            task.call();
        }
    }

    public static void repeatTaskSerially(Callable<Void> task)
            throws Exception{
        repeatTaskSerially(task, 200);
    }

    public static byte[] null2Empty(byte[] src) {
        return src == null ? EMPTY : src;
    }

    public static byte[] data(int size, byte b) {
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            data[i] = b;
        }
        return data;
    }

    public static byte[] data(int size) {
        return data(size, (byte) 'a');
    }

    public static byte[] dataKB(int sizeInKB) {
        return data(sizeInKB * 1024);
    }

    public static byte[] dataMB(int sizeInMB) {
        return dataKB(sizeInMB * 1024);
    }

    public static KeyPair keyPair(String publicKeyHex, String privateKeyHex) {
        SM2PublicKey publicKeySpec = new SM2PublicKey(toBytes(publicKeyHex));
        SM2PrivateKey privateKeySpec = new SM2PrivateKey(toBytes(privateKeyHex));

        return new KeyPair(publicKeySpec, privateKeySpec);
    }

    @FunctionalInterface
    public interface Executable {

        void execute() throws Exception;
    }
}
