/*
 * Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
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

import com.tencent.kona.crypto.CryptoUtils;

import javax.crypto.KeyGenerator;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class SSLInsts {

    static final String PROV_NAME = CryptoUtils.privilegedGetProperty(
            "com.tencent.kona.ssl.provider.name", KonaSSLProvider.NAME);

    private static final Set<String> KEY_MANAGER_FACTORY_ALGOS
            = new HashSet<>(Arrays.asList("SunX509", "NewSunX509"));

    public static KeyManagerFactory getKeyManagerFactory(String algorithm)
            throws NoSuchAlgorithmException {
        KeyManagerFactory keyManagerFactory  = null;
        if (KEY_MANAGER_FACTORY_ALGOS.contains(algorithm)) {
            try {
                keyManagerFactory = KeyManagerFactory.getInstance(algorithm, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            keyManagerFactory = KeyManagerFactory.getInstance(algorithm);
        }
        return keyManagerFactory;
    }

    private static final Set<String> TRUST_MANAGER_FACTORY_ALGOS
            = new HashSet<>(Arrays.asList("SunX509", "PKIX"));

    public static TrustManagerFactory getTrustManagerFactory(String algorithm)
            throws NoSuchAlgorithmException {
        TrustManagerFactory trustManagerFactory  = null;
        if (TRUST_MANAGER_FACTORY_ALGOS.contains(algorithm)) {
            try {
                trustManagerFactory = TrustManagerFactory.getInstance(algorithm, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
        }
        return trustManagerFactory;
    }

    private static final Set<String> SSL_CONTEXT_PROTOCOLS
            = new HashSet<>(Arrays.asList(
                    "TLCPv1.1", "TLSv1.2", "TLSv1.3", "TLCP", "TLS", "Default"));

    public static SSLContext getSSLContext(String protocol)
            throws NoSuchAlgorithmException {
        SSLContext context  = null;
        if (SSL_CONTEXT_PROTOCOLS.contains(protocol)) {
            try {
                context = SSLContext.getInstance(protocol, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            context = SSLContext.getInstance(protocol);
        }
        return context;
    }

    private static final Set<String> KEY_GEN_ALGOS
            = new HashSet<>(Arrays.asList(
                    "SunTlsPrf", "SunTls12Prf",
                    "SunTlsMasterSecret", "SunTlsKeyMaterial",
                    "TlcpSM2PremasterSecret"));

    public static KeyGenerator getKeyGenerator(String protocol)
            throws NoSuchAlgorithmException {
        KeyGenerator keyGen  = null;
        if (KEY_GEN_ALGOS.contains(protocol)) {
            try {
                keyGen = KeyGenerator.getInstance(protocol, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            keyGen = KeyGenerator.getInstance(protocol);
        }
        return keyGen;
    }
}
