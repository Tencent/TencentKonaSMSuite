package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.TestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.Security;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The test for SM3 with BouncyCastle.
 */
public class SM3WithBCTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testDigest() throws Exception {
        byte[] message = toBytes("616263");

        MessageDigest md = MessageDigest.getInstance("SM3", PROVIDER);
        byte[] digest = md.digest(message);

        MessageDigest mdBC = MessageDigest.getInstance("SM3", "BC");
        byte[] digestBC = mdBC.digest(message);

        Assertions.assertArrayEquals(digestBC, digest);
    }
}
