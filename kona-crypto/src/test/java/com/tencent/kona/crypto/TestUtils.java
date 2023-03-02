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

    public static void checkNPE(Executable executable) {
        checkThrowable(NullPointerException.class, executable);
    }

    public static void checkIAE(Executable executable) {
        checkThrowable(IllegalArgumentException.class, executable);
    }

    public static void checkISE(Executable executable) {
        checkThrowable(IllegalStateException.class, executable);
    }

    public static void checkAIOOBE(Executable executable) {
        checkThrowable(ArrayIndexOutOfBoundsException.class, executable);
    }

    public static void checkThrowable(Class<? extends Throwable> throwableClass,
                                      Executable executable,
                                      boolean requiredExpectedException) {
        try {
            executable.execute();
            if (requiredExpectedException) {
                throw new AssertionError("Expected exception did not raise");
            } else {
                System.out.println("Expected exception did not raise, " +
                        "though that's not a matter");
            }
        } catch(Throwable e) {
            if (!throwableClass.isInstance(e)) {
                throw new AssertionError("Unexpected exception: ", e);
            }
        }
    }

    public static void checkThrowable(Class<? extends Throwable> throwableClass,
                                      Executable executable) {
        checkThrowable(throwableClass, executable, true);
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
