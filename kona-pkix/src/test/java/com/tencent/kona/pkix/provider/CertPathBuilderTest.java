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

import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The test for CertPathBuilder.
 */
public class CertPathBuilderTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testGetCertPathBuilder() throws Exception {
        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", "KonaPKIX");
        Assertions.assertTrue(cpb.getProvider() instanceof KonaPKIXProvider);
    }

    @Test
    public void testBuild() throws Exception {
        testBuild("ee-p256ecdsa-p256ecdsa-p256ecdsa.crt",
                  "intca-p256ecdsa-p256ecdsa.crt",
                  "ca-p256ecdsa.crt");
        testBuild("ee-sm2sm2-sm2sm2-sm2sm2.crt",
                  "intca-sm2sm2-sm2sm2.crt",
                  "ca-sm2sm2.crt");
    }

    private void testBuild(String ee, String intCa, String ca) throws Exception {
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(TestUtils.certAsFile(ee));

        Set<TrustAnchor> anchors = new HashSet<>();
        anchors.add(new TrustAnchor(TestUtils.certAsFile(ca), null));
        PKIXBuilderParameters params = new PKIXBuilderParameters(
                anchors, selector);
        params.setRevocationEnabled(false);

        Collection<X509Certificate> certs = new HashSet<>();
        certs.add(TestUtils.certAsFile(ee));
        certs.add(TestUtils.certAsFile(intCa));
        CertStore certStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(certs), "KonaPKIX");
        params.addCertStore(certStore);

        CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX", "KonaPKIX");
        CertPathBuilderResult result = cpb.build(params);
        CertPath certPath = result.getCertPath();

        @SuppressWarnings("unchecked")
        List<X509Certificate> certPathCerts
                = (List<X509Certificate>) certPath.getCertificates();
        Assertions.assertEquals(certPathCerts.get(0), TestUtils.certAsFile(ee));
        Assertions.assertEquals(certPathCerts.get(1), TestUtils.certAsFile(intCa));
    }
}
