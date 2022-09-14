package com.tencent.kona.crypto.provider;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The test for SM3 engine.
 */
public class SM3EngineTest {

    private static final byte[] MESSAGE_SHORT = toBytes("616263");
    private static final byte[] DIGEST_SHORT = toBytes(
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");

    private static final byte[] MESSAGE_LONG = toBytes(
            "61626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364");
    private static final byte[] DIGEST_LONG = toBytes(
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");

    @Test
    public void testKAT() {
        testDigest(MESSAGE_SHORT, DIGEST_SHORT);
        testDigest(MESSAGE_LONG, DIGEST_LONG);
    }

    private void testDigest(byte[] message, byte[] expectedDigest) {
        byte[] digest = new byte[32];

        SM3Engine sm3Engine = new SM3Engine();
        sm3Engine.update(message);
        sm3Engine.doFinal(digest);

        Assertions.assertArrayEquals(expectedDigest, digest);
    }

    @Test
    public void testUpdateBulk() {
        testUpdateBulk(MESSAGE_SHORT, DIGEST_SHORT);
        testUpdateBulk(MESSAGE_LONG, DIGEST_LONG);
    }

    private void testUpdateBulk(byte[] message, byte[] expectedDigest) {
        byte[] digest = new byte[32];

        SM3Engine sm3Engine = new SM3Engine();
        sm3Engine.update(message, 0, message.length / 3);
        sm3Engine.update(message, message.length / 3, message.length / 3);
        sm3Engine.update(message, message.length / 3 * 2, message.length - message.length / 3 * 2);
        sm3Engine.doFinal(digest);

        Assertions.assertArrayEquals(expectedDigest, digest);
    }

    @Test
    public void testUpdate() {
        testUpdate(MESSAGE_SHORT, DIGEST_SHORT);
        testUpdate(MESSAGE_LONG, DIGEST_LONG);
    }

    private void testUpdate(byte[] message, byte[] expectedDigest) {
        byte[] digest = new byte[32];

        SM3Engine sm3Engine = new SM3Engine();
        for(byte b : message) {
            sm3Engine.update(b);
        }
        sm3Engine.doFinal(digest);

        Assertions.assertArrayEquals(expectedDigest, digest);
    }
}
