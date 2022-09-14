package com.tencent.kona;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

/**
 * The Kona Provider.
 */
public class KonaProvider extends Provider {

    private static final long serialVersionUID = 1207190468265916803L;

    private static final String INFO = "Kona PKIX Provider "
            + "supporting ShangMi crypto, PKI and secure protocols";

    public static final String NAME = "Kona";

    private static final double VERSION_NUM = 1.0D;

    static {
        privilegedSetProperty("com.tencent.kona.crypto.provider.name", NAME);
        privilegedSetProperty("com.tencent.kona.pkix.provider.name", NAME);
        privilegedSetProperty("com.tencent.kona.ssl.provider.name", NAME);
    }

    public KonaProvider() {
        super(NAME, VERSION_NUM, INFO);

        AccessController.doPrivileged(
                (PrivilegedAction<Void>) () -> {
                    putEntries(this);

                    return null;
                });
    }

    private static void putEntries(Provider provider) {
        try {
            putEntries("com.tencent.kona.crypto.KonaCryptoProvider", provider);
            putEntries("com.tencent.kona.pkix.KonaPKIXProvider", provider);
            putEntries("com.tencent.kona.ssl.KonaSSLProvider", provider);
        } catch (Exception e) {
            throw new IllegalStateException("Put provider entries failed", e);
        }
    }

    private static void putEntries(String providerClass, Provider provider)
            throws NoSuchMethodException,
            InvocationTargetException, IllegalAccessException {
        Class<?> clazz = null;
        try {
            clazz = Class.forName(providerClass);
        } catch (ClassNotFoundException cnfe) {
            // This provider is not in the classpath
        }

        if (clazz != null) {
            Method method = clazz.getDeclaredMethod("putEntries", Provider.class);
            method.setAccessible(true);
            method.invoke(clazz, provider);
        }
    }

    private static String privilegedSetProperty(String key, String value) {
        return AccessController.doPrivileged(
                (PrivilegedAction<String>) () -> System.setProperty(key, value));
    }
}
