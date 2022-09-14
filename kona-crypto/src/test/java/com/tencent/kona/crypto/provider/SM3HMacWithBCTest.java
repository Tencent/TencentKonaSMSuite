package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.TestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The test for SM3 HMAC with BouncyCastle.
 */
public class SM3HMacWithBCTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testSM3HMac() throws Exception {
        byte[] message = toBytes("616263");

        Mac sm3HMac = Mac.getInstance("SM3HMac", PROVIDER);
        Mac sm3HMacBC = Mac.getInstance("HMACSM3", "BC");

        SecretKey secretKey = new SecretKeySpec(
                toBytes("0123456789abcdef0123456789abcdef"), "SM4");

        sm3HMac.init(secretKey);
        sm3HMacBC.init(secretKey);

        byte[] mac = sm3HMac.doFinal(message);
        byte[] macBC = sm3HMac.doFinal(message);

        Assertions.assertArrayEquals(macBC, mac);
    }
}
