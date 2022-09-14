package com.tencent.kona;

import java.security.Security;

public class TestUtils {

    public static final String PROVIDER = KonaProvider.NAME;

    public static void addProviders() {
        Security.insertProviderAt(new KonaProvider(), 1);
    }
}
