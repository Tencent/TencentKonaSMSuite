package com.tencent.kona.jdk.internal.misc;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static com.tencent.kona.crypto.CryptoUtils.isAndroid;
import static com.tencent.kona.crypto.CryptoUtils.isJdk8;
import static com.tencent.kona.crypto.CryptoUtils.privilegedGetBoolProperty;

/**
 * The utilities for operating Unsafe cross JDK 8, 11 and 17.
 */
public class UnsafeUtil {

    private static final boolean USE_UNSAFE
            = privilegedGetBoolProperty("com.tencent.misc.useUnsafe", "false");

    private static final Method setMemory;
    private static final Object unsafe;

    static {
        Class<?> unsafeClass = null;

        if (useUnsafe()) {
            try {
                if (isJdk8()) {
                    unsafeClass = Class.forName("sun.misc.Unsafe");
                } else {
                    unsafeClass = Class.forName("jdk.internal.misc.Unsafe");
                }
            } catch (ClassNotFoundException e) {
                throw new InternalError("Cannot get Unsafe class", e);
            }
        }

        if (unsafeClass != null) {
            Method getUnsafeMethod;
            try {
                getUnsafeMethod = unsafeClass.getMethod("getUnsafe");
                setMemory = unsafeClass.getMethod("setMemory",
                        long.class, long.class, byte.class);
            } catch (NoSuchMethodException e) {
                throw new InternalError("Cannot get method", e);
            }

            getUnsafeMethod.setAccessible(true);
            try {
                unsafe = getUnsafeMethod.invoke(null);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new InternalError("Cannot get Unsafe object", e);
            }
        } else {
            setMemory = null;
            unsafe = null;
        }
    }

    private static boolean useUnsafe() {
        return USE_UNSAFE && !isAndroid();
    }

    public static void setMemory(long address, long bytes, byte value) {
        if (setMemory == null) {
            return;
        }

        try {
            setMemory.invoke(unsafe, address, bytes, value);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException("setMemory failed", e);
        }
    }
}
