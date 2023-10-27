package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.InvalidParameterException;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;

/**
 * The test for SM4 key generator.
 */
public class SM4KeyGeneratorTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testKeyGen() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", PROVIDER);

        Assertions.assertThrows(
                InvalidParameterException.class, ()-> keyGen.init(127));

        SecretKey key = keyGen.generateKey();
        Assertions.assertEquals(16, key.getEncoded().length);

        keyGen.init(128);
        key = keyGen.generateKey();
        Assertions.assertEquals(16, key.getEncoded().length);

        Assertions.assertThrows(
                InvalidParameterException.class, ()-> keyGen.init(256));
    }

    @Test
    public void testKeyGenParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testKeyGen();
            return null;
        });
    }

    @Test
    public void testKeyGenSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testKeyGen();
            return null;
        });
    }
}
