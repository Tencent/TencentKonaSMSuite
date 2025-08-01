/*
 * Copyright (C) 2022, 2024, Tencent. All rights reserved.
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

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

/**
 * The Kona PKIX Provider.
 */
public class KonaPKIXProvider extends Provider {

    private static final long serialVersionUID = 1207190468265916803L;

    private static final String INFO = "Kona PKIX Provider "
            + "supporting ShangMi certificate and validation";

    static final String NAME = "KonaPKIX";

    private static final double VERSION_NUM = 1.0D;

    private static volatile KonaPKIXProvider instance = null;

    public KonaPKIXProvider() {
        super(NAME, VERSION_NUM, INFO);

        AccessController.doPrivileged(
                (PrivilegedAction<Void>) () -> {
                    putEntries(this);

                    return null;
                });
    }

    private static void putEntries(Provider provider) {
        provider.put("CertificateFactory.X.509",
                "com.tencent.kona.sun.security.provider.X509Factory");

        provider.put("KeyStore.PKCS12",
                "com.tencent.kona.sun.security.pkcs12.PKCS12KeyStore");
        provider.put("KeyStore.JKS",
                "com.tencent.kona.sun.security.provider.JavaKeyStore$JKS");

        provider.put("CertPathValidator.PKIX",
                "com.tencent.kona.sun.security.provider.certpath.PKIXCertPathValidator");
        provider.put("CertPathBuilder.PKIX",
                "com.tencent.kona.sun.security.provider.certpath.SunCertPathBuilder");
        provider.put("CertStore.Collection",
                "com.tencent.kona.sun.security.provider.certpath.CollectionCertStore");
    }

    public static KonaPKIXProvider instance() {
        if (instance == null) {
            instance = new KonaPKIXProvider();
        }
        return instance;
    }
}
