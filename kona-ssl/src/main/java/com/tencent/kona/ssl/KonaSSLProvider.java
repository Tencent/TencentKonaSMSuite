/*
 * Copyright (C) 2022, 2024, THL A29 Limited, a Tencent company. All rights reserved.
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

package com.tencent.kona.ssl;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

/**
 * The Kona SSL/TLS Provider.
 */
public class KonaSSLProvider extends Provider {

    private static final long serialVersionUID = 1207190468265916803L;

    private static final String INFO = "Kona SSL/TLS Provider "
            + "supporting RFC 8998 and Transport Layer Cryptography Protocol (TLCP)";

    static final String NAME = "KonaSSL";

    private static final double VERSION_NUM = 1.0D;

    public KonaSSLProvider() {
        super(NAME, VERSION_NUM, INFO);

        AccessController.doPrivileged(
                (PrivilegedAction<Void>) () -> {
                    putEntries(this);

                    return null;
                });
    }

    private static void putEntries(Provider provider) {
        provider.put("KeyManagerFactory.SunX509",
                "com.tencent.kona.sun.security.ssl.KeyManagerFactoryImpl$SunX509");
        provider.put("KeyManagerFactory.NewSunX509",
                "com.tencent.kona.sun.security.ssl.KeyManagerFactoryImpl$X509");
        provider.put("Alg.Alias.KeyManagerFactory.PKIX", "NewSunX509");

        provider.put("TrustManagerFactory.SunX509",
                "com.tencent.kona.sun.security.ssl.TrustManagerFactoryImpl$SimpleFactory");
        provider.put("TrustManagerFactory.PKIX",
                "com.tencent.kona.sun.security.ssl.TrustManagerFactoryImpl$PKIXFactory");
        provider.put("Alg.Alias.TrustManagerFactory.TencentPKIX", "PKIX");
        provider.put("Alg.Alias.TrustManagerFactory.X509", "PKIX");
        provider.put("Alg.Alias.TrustManagerFactory.X.509", "PKIX");

        provider.put("SSLContext.TLCPv1.1",
                "com.tencent.kona.sun.security.ssl.TLCPContextImpl$TLCP11Context");
        provider.put("SSLContext.TLSv1.2",
                "com.tencent.kona.sun.security.ssl.SSLContextImpl$TLS12Context");
        provider.put("SSLContext.TLSv1.3",
                "com.tencent.kona.sun.security.ssl.SSLContextImpl$TLS13Context");

        provider.put("SSLContext.TLCP",
                "com.tencent.kona.sun.security.ssl.TLCPContextImpl$TLCPContext");
        provider.put("SSLContext.TLS",
                "com.tencent.kona.sun.security.ssl.SSLContextImpl$TLSContext");
        provider.put("Alg.Alias.SSLContext.SSL", "TLS");

        provider.put("SSLContext.Default",
                "com.tencent.kona.sun.security.ssl.SSLContextImpl$DefaultSSLContext");

        provider.put("KeyGenerator.SunTlsPrf",
                "com.tencent.kona.sun.security.provider.TlsPrfGenerator$V10");
        provider.put("KeyGenerator.SunTls12Prf",
                "com.tencent.kona.sun.security.provider.TlsPrfGenerator$V12");

        provider.put("KeyGenerator.SunTlsMasterSecret",
                "com.tencent.kona.sun.security.provider.TlsMasterSecretGenerator");
        provider.put("Alg.Alias.KeyGenerator.SunTls12MasterSecret",
                "SunTlsMasterSecret");
        provider.put("Alg.Alias.KeyGenerator.SunTlsExtendedMasterSecret",
                "SunTlsMasterSecret");

        provider.put("KeyGenerator.SunTlsKeyMaterial",
                "com.tencent.kona.sun.security.provider.TlsKeyMaterialGenerator");
        provider.put("Alg.Alias.KeyGenerator.SunTls12KeyMaterial",
                "SunTlsKeyMaterial");

        provider.put("KeyGenerator.SunTlsRsaPremasterSecret",
                "com.tencent.kona.sun.security.provider.TlsRsaPremasterSecretGenerator");
        provider.put("Alg.Alias.KeyGenerator.SunTls12RsaPremasterSecret", "SunTlsRsaPremasterSecret");
    }
}
