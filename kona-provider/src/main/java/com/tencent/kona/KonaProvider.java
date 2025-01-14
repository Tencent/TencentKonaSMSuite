/*
 * Copyright (C) 2022, 2025, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. THL A29 Limited designates
 * this particular file as subject to the "Classpath" exception as provided
 * in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

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

    private static volatile KonaProvider instance = null;

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
        String defaultCrypto = KonaUtils.defaultCrypto();

        String defaultCryptoProvider;
        if ("Native".equalsIgnoreCase(defaultCrypto)) {
            defaultCryptoProvider = "com.tencent.kona.crypto.KonaCryptoNativeProvider";
        } else if ("NativeOneShot".equalsIgnoreCase(defaultCrypto)) {
            defaultCryptoProvider = "com.tencent.kona.crypto.KonaCryptoNativeOneShotProvider";
        } else {
            defaultCryptoProvider = "com.tencent.kona.crypto.KonaCryptoProvider";
        }

        try {
            putEntries(defaultCryptoProvider, provider);
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

    public static String privilegedGetProperty(String key, String def) {
        return AccessController.doPrivileged(
                (PrivilegedAction<String>) () -> System.getProperty(key, def));
    }

    private static String privilegedSetProperty(String key, String value) {
        return AccessController.doPrivileged(
                (PrivilegedAction<String>) () -> System.setProperty(key, value));
    }

    public static KonaProvider instance() {
        if (instance == null) {
            instance = new KonaProvider();
        }

        return instance;
    }
}
