package com.tencent.kona.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * The test for Utils.
 */
public class CryptoUtilsTest {

    @Test
    public void testToHex() {
        Assertions.assertEquals(
                "01234567",
                CryptoUtils.toHex(new byte[] { 1, 35, 69, 103 }));
    }

    @Test
    public void testToBytes() {
        Assertions.assertArrayEquals(
                new byte[] { 1, 35, 69, 103 },
                CryptoUtils.toBytes("01234567"));
    }
}
