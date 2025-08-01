/*
 * Copyright (C) 2022, 2023, Tencent. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package com.tencent.kona.pkix.provider;

import com.tencent.kona.pkix.KonaPKIXProvider;
import com.tencent.kona.pkix.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;

/**
 * The test for CertStore.
 */
public class CertStoreTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testGetCertStore() throws Exception {
        CertStore certStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(), "KonaPKIX");
        Assertions.assertTrue(certStore.getProvider() instanceof KonaPKIXProvider);
    }

    @Test
    public void testGetCertificates() throws Exception {
        testGetCertificates(
                "ee-rsarsa-rsarsa-rsarsa.crt",
                "intca-rsarsa-rsarsa.crt",
                "ca-rsarsa.crt");
        testGetCertificates(
                "ee-sm2sm2-sm2sm2-sm2sm2.crt",
                "intca-sm2sm2-sm2sm2.crt",
                "ca-sm2sm2.crt");
        testGetCertificates(
                "ee-p256ecdsa-p256ecdsa-p256ecdsa.crt",
                "intca-p256ecdsa-p256ecdsa.crt",
                "ca-p256ecdsa.crt");
    }

    private void testGetCertificates(String ee, String intCa, String ca)
            throws Exception {
        Collection<X509Certificate> certs = new HashSet<>();
        X509Certificate target = TestUtils.certAsFile(ee);
        certs.add(TestUtils.certAsFile(ee));
        certs.add(TestUtils.certAsFile(intCa));
        certs.add(TestUtils.certAsFile(ca));

        CertStore certStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(certs), "KonaPKIX");

        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setCertificate(target);

        Collection<? extends Certificate> foundCerts
                = certStore.getCertificates(certSelector);
        Assertions.assertEquals(
                target.getSerialNumber(),
                ((X509Certificate) foundCerts.iterator().next())
                        .getSerialNumber());
    }
}
