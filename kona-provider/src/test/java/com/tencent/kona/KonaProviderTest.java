package com.tencent.kona;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;

/**
 * The test for this provider.
 */
public class KonaProviderTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testAddProvider() {
        Assertions.assertNotNull(Security.getProvider(TestUtils.PROVIDER));
    }
}
