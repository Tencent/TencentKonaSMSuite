/*
 * Copyright (C) 2022, 2024, THL A29 Limited, a Tencent company. All rights reserved.
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

import com.tencent.kona.crypto.spec.SM2PrivateKeySpec;
import com.tencent.kona.crypto.spec.SM2PublicKeySpec;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
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
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("SM2");

            PrivateKey privateKey = keyFactory.generatePrivate(
                    new SM2PrivateKeySpec(toBytes(privateKeyHex)));
            PublicKey publicKey = keyFactory.generatePublic(
                    new SM2PublicKeySpec(toBytes(publicKeyHex)));
            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw new RuntimeException("Create key pair failed", e);
        }
    }

    public static ECPrivateKey privateKey(String hex) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2");
        return (ECPrivateKey) keyFactory.generatePrivate(
                new SM2PrivateKeySpec(toBytes(hex)));
    }

    public static ECPublicKey publicKey(String hex) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2");
        return (ECPublicKey) keyFactory.generatePublic(
                new SM2PublicKeySpec(toBytes(hex)));
    }

    @FunctionalInterface
    public interface Executable {

        void execute() throws Exception;
    }
}
