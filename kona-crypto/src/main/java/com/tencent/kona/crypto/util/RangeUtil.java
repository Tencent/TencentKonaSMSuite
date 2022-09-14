package com.tencent.kona.crypto.util;

import java.security.ProviderException;
import java.util.List;
import java.util.function.BiFunction;

import com.tencent.kona.jdk.internal.util.Preconditions;

/**
 * This class holds the various utility methods for range checks.
 */
public final class RangeUtil {

    private static final BiFunction<String, List<Number>, ArrayIndexOutOfBoundsException>
            AIOOBE_SUPPLIER = Preconditions.outOfBoundsExceptionFormatter(
                    ArrayIndexOutOfBoundsException::new);

    public static void blockSizeCheck(int len, int blockSize) {
        if ((len % blockSize) != 0) {
            throw new ProviderException("Internal error in input buffering");
        }
    }

    public static void nullAndBoundsCheck(byte[] array, int offset, int len) {
        // NPE is thrown when array is null
        Preconditions.checkFromIndexSize(offset, len, array.length, AIOOBE_SUPPLIER);
    }
}
