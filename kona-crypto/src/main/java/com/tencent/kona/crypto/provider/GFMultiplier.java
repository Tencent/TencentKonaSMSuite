package com.tencent.kona.crypto.provider;

import static com.tencent.kona.crypto.CryptoUtils.bytes8ToLong;

/**
 * The abstract implementation on the Galois Field multiplication.
 */
abstract class GFMultiplier {

    final long[] subkeyWords = new long[2];

    // Convert key from 16-bytes to 2-longs
    GFMultiplier(byte[] subkeyH) {
        subkeyWords[0] = bytes8ToLong(subkeyH, 0);
        subkeyWords[1] = bytes8ToLong(subkeyH, 8);
    }

    abstract void multiply(long[] block);
}
