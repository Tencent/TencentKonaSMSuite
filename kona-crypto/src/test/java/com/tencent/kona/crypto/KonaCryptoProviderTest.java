package com.tencent.kona.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.security.Security;

public class KonaCryptoProviderTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testAddProvider() {
        Provider[] providers = Security.getProviders();
        Assertions.assertEquals(
                TestUtils.PROVIDER, providers[providers.length - 1].getName());
    }
}
