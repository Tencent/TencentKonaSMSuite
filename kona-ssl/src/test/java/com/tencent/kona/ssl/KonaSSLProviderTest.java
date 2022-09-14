package com.tencent.kona.ssl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * The test for this provider.
 */
public class KonaSSLProviderTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testAddProvider() {
        Assertions.assertNotNull(Security.getProvider(TestUtils.PROVIDER));
    }

    @Test
    public void testProtocols() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.3", TestUtils.PROVIDER);
        Assertions.assertEquals("TLSv1.3", context.getProtocol());

        context = SSLContext.getInstance("TLSv1.2", TestUtils.PROVIDER);
        Assertions.assertEquals("TLSv1.2", context.getProtocol());

        Assertions.assertThrows(NoSuchAlgorithmException.class,
                () -> SSLContext.getInstance("TLSv1.1", TestUtils.PROVIDER));

        Assertions.assertThrows(NoSuchAlgorithmException.class,
                () -> SSLContext.getInstance("TLSv1", TestUtils.PROVIDER));

        Assertions.assertThrows(NoSuchAlgorithmException.class,
                () -> SSLContext.getInstance("SSLv3", TestUtils.PROVIDER));
    }
}
