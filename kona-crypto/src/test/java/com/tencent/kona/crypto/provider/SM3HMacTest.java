package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.InvalidParameterException;
import java.security.SecureRandom;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static com.tencent.kona.crypto.util.Constants.SM3_HMAC_LEN;
import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * The test for SM3 HMAC.
 */
public class SM3HMacTest {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] MESSAGE = toBytes("616263");

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testSM3HMacKeyGen() throws Exception {
        KeyGenerator sm3HMacKeyGen
                = KeyGenerator.getInstance("SM3HMac", PROVIDER);

        TestUtils.checkThrowable(
                InvalidParameterException.class, ()-> sm3HMacKeyGen.init(127));

        sm3HMacKeyGen.init(128);
        SecretKey key = sm3HMacKeyGen.generateKey();
        Assertions.assertEquals(16, key.getEncoded().length);

        sm3HMacKeyGen.init(new SecureRandom());
        key = sm3HMacKeyGen.generateKey();
        Assertions.assertEquals(32, key.getEncoded().length);
    }

    @Test
    public void testSM3HMacKeyGenParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testSM3HMacKeyGen();
            return null;
        });
    }

    @Test
    public void testSM3HMacKeyGenSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testSM3HMacKeyGen();
            return null;
        });
    }

    @Test
    public void testSM3HMac() throws Exception {
        Mac sm3HMac = Mac.getInstance("SM3HMac", PROVIDER);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "SM4");
        sm3HMac.init(keySpec);
        byte[] mac = sm3HMac.doFinal(toBytes("616263"));
        Assertions.assertEquals(SM3_HMAC_LEN, mac.length);
    }

    @Test
    public void testUpdateByte() throws Exception {
        Mac sm3HMac = Mac.getInstance("SM3HMac", PROVIDER);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "SM4");
        sm3HMac.init(keySpec);
        for (byte b : MESSAGE) {
            sm3HMac.update(b);
        }
        byte[] mac = sm3HMac.doFinal();
        Assertions.assertEquals(SM3_HMAC_LEN, mac.length);
    }

    @Test
    public void testUpdateBytes() throws Exception {
        Mac sm3HMac = Mac.getInstance("SM3HMac", PROVIDER);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "SM4");
        sm3HMac.init(keySpec);
        sm3HMac.update(MESSAGE, 0, MESSAGE.length / 2);
        sm3HMac.update(MESSAGE, MESSAGE.length / 2, MESSAGE.length - MESSAGE.length / 2);
        byte[] mac = sm3HMac.doFinal();
        Assertions.assertEquals(SM3_HMAC_LEN, mac.length);
    }

    @Test
    public void testBigData() throws Exception {
        Mac sm3HMac = Mac.getInstance("SM3HMac", PROVIDER);
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "SM4");
        sm3HMac.init(keySpec);
        byte[] mac = sm3HMac.doFinal(TestUtils.dataMB(10));
        Assertions.assertEquals(SM3_HMAC_LEN, mac.length);
    }

    @Test
    public void testSM3HMacParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testSM3HMac();
            return null;
        });
    }

    @Test
    public void testSM3HMacSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testSM3HMac();
            return null;
        });
    }
}
