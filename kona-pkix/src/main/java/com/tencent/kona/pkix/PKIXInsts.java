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

package com.tencent.kona.pkix;

import com.tencent.kona.crypto.CryptoUtils;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class PKIXInsts {

    static final String PROV_NAME = CryptoUtils.privilegedGetProperty(
            "com.tencent.kona.pkix.provider.name", KonaPKIXProvider.NAME);

    private static final Set<String> CERTIFICATE_FACTORY_TYPES
            = new HashSet<>(Collections.singletonList("X.509"));

    public static CertificateFactory getCertificateFactory(String type)
            throws CertificateException {
        CertificateFactory certificateFactory  = null;
        if (CERTIFICATE_FACTORY_TYPES.contains(type)) {
            try {
                certificateFactory = CertificateFactory.getInstance(type, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            certificateFactory = CertificateFactory.getInstance(type);
        }
        return certificateFactory;
    }

    private static final Set<String> KEY_STORE_TYPES
            = new HashSet<>(Arrays.asList("PKCS12", "JKS"));

    public static KeyStore getKeyStore(String type)
            throws KeyStoreException {
        KeyStore keyStore  = null;
        if (KEY_STORE_TYPES.contains(type)) {
            try {
                keyStore = KeyStore.getInstance(type, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            keyStore = KeyStore.getInstance(type);
        }
        return keyStore;
    }

    private static final Set<String> CERT_PATH_VALIDATOR_ALGOS
            = new HashSet<>(Collections.singletonList("PKIX"));

    public static CertPathValidator getCertPathValidator(String algorithm)
            throws NoSuchAlgorithmException {
        CertPathValidator certPathValidator  = null;
        if (CERT_PATH_VALIDATOR_ALGOS.contains(algorithm)) {
            try {
                certPathValidator = CertPathValidator.getInstance(algorithm, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            certPathValidator = CertPathValidator.getInstance(algorithm);
        }
        return certPathValidator;
    }

    private static final Set<String> CERT_PATH_BUILDER_ALGOS
            = new HashSet<>(Collections.singletonList("PKIX"));

    public static CertPathBuilder getCertPathBuilder(String algorithm)
            throws NoSuchAlgorithmException {
        CertPathBuilder certPathBuilder  = null;
        if (CERT_PATH_BUILDER_ALGOS.contains(algorithm)) {
            try {
                certPathBuilder = CertPathBuilder.getInstance(algorithm, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            certPathBuilder = CertPathBuilder.getInstance(algorithm);
        }
        return certPathBuilder;
    }

    private static final Set<String> CERT_STORE_TYPES
            = new HashSet<>(Collections.singletonList("Collection"));

    public static CertStore getCertStore(String type, CertStoreParameters params)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        CertStore certStore  = null;
        if (CERT_STORE_TYPES.contains(type)) {
            try {
                certStore = CertStore.getInstance(type, params, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            certStore = CertStore.getInstance(type, params);
        }
        return certStore;
    }
}
