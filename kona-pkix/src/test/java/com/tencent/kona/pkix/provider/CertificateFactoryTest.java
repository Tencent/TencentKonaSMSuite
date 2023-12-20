/*
 * Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
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

import com.tencent.kona.crypto.util.Constants;
import com.tencent.kona.pkix.KonaPKIXProvider;
import com.tencent.kona.pkix.TestUtils;
import com.tencent.kona.sun.security.util.KnownOIDs;
import com.tencent.kona.sun.security.util.ObjectIdentifier;
import com.tencent.kona.sun.security.x509.AlgorithmId;
import com.tencent.kona.sun.security.x509.SMCertificate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * The test for CertificateFactory.
 */
public class CertificateFactoryTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testGetCertificateFactory() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "KonaPKIX");
        Assertions.assertTrue(cf.getProvider() instanceof KonaPKIXProvider);
    }

    @Test
    public void testGenCertCaRsaRsa() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "KonaPKIX");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(TestUtils.certBytes("ca-rsarsa.crt")));
        RSAPublicKey pubKey = (RSAPublicKey) cert.getPublicKey();
        Assertions.assertEquals("RSA", pubKey.getAlgorithm());
        Assertions.assertEquals(KnownOIDs.SHA256withRSA.value(), cert.getSigAlgOID());
        Assertions.assertEquals("SHA256withRSA", cert.getSigAlgName());
    }

    @Test
    public void testGenCertCaP256Ecdsa() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "KonaPKIX");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(TestUtils.certBytes("ca-p256ecdsa.crt")));
        ECPublicKey pubKey = (ECPublicKey) cert.getPublicKey();
        Assertions.assertEquals("EC", pubKey.getAlgorithm());
        Assertions.assertEquals(KnownOIDs.SHA256withECDSA.value(), cert.getSigAlgOID());
        Assertions.assertEquals("SHA256withECDSA", cert.getSigAlgName());
    }

    @Test
    public void testGenCertCaP256Sm2() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "KonaPKIX");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(TestUtils.certBytes("ca-p256sm2.crt")));
        ECPublicKey pubKey = (ECPublicKey) cert.getPublicKey();
        Assertions.assertEquals("EC", pubKey.getAlgorithm());
        Assertions.assertEquals(
                KnownOIDs.SM3withSM2.value(),
                cert.getSigAlgOID());
        Assertions.assertEquals("SM3withSM2", cert.getSigAlgName());
    }

    @Test
    public void testGenCertCaSm2Ecdsa() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "KonaPKIX");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(TestUtils.certBytes("ca-sm2ecdsa.crt")));
        ECPublicKey pubKey = (ECPublicKey) cert.getPublicKey();
        Assertions.assertEquals("EC", pubKey.getAlgorithm());
        Assertions.assertEquals(
                KnownOIDs.SHA256withECDSA.value(),
                cert.getSigAlgOID());
        Assertions.assertEquals("SHA256withECDSA", cert.getSigAlgName());
    }

    @Test
    public void testGenCertCaSm2Sm2() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "KonaPKIX");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(TestUtils.certBytes("ca-sm2sm2.crt")));
        ECPublicKey pubKey = (ECPublicKey) cert.getPublicKey();
        Assertions.assertEquals("EC", pubKey.getAlgorithm());
        Assertions.assertEquals(
                KnownOIDs.SM3withSM2.value(),
                cert.getSigAlgOID());
        Assertions.assertEquals("SM3withSM2", cert.getSigAlgName());
    }

    @Test
    public void testSetId() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "KonaPKIX");
        SMCertificate sm2Cert = (SMCertificate) cf.generateCertificate(
                new ByteArrayInputStream(TestUtils.certBytes("ca-sm2sm2-id.crt")));
        Assertions.assertArrayEquals(
                Constants.defaultId(), sm2Cert.getId());

        // Set custom ID
        byte[] customId = "12345678".getBytes(StandardCharsets.UTF_8);
        sm2Cert.setId(customId);
        Assertions.assertArrayEquals(customId, sm2Cert.getId());

        // ID cannot be changed for the same certificate
        Assertions.assertThrows(IllegalStateException.class,
                () -> sm2Cert.setId(new byte[] { 0, 1, 2, 3, 2, 1, 0 }));

        SMCertificate ecdsaCert = (SMCertificate) cf.generateCertificate(
                new ByteArrayInputStream(TestUtils.certBytes("ca-p256ecdsa.crt")));
        // ECDSA certificate cannot have ID
        Assertions.assertNull(ecdsaCert.getId());
        // ID cannot be assigned to ECDSA certificate
        Assertions.assertThrows(IllegalStateException.class,
                () -> ecdsaCert.setId(customId));
    }

    @Test
    public void testGenCerts() throws Exception {
        byte[] certBytes = TestUtils.concatCertFiles(
                "ca-rsarsa.crt",
                "ca-p256ecdsa.crt",
                "ca-p256sm2.crt",
                "ca-sm2sm2.crt",
                "ca-sm2ecdsa.crt").getBytes(StandardCharsets.UTF_8);

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "KonaPKIX");
        Collection<? extends Certificate> certs = cf.generateCertificates(
                new ByteArrayInputStream(certBytes));
        Iterator<? extends Certificate> iterator = certs.iterator();
        X509Certificate cert = (X509Certificate) iterator.next();
        Assertions.assertEquals("CN=ca-rsarsa", cert.getSubjectDN().getName());
        cert = (X509Certificate) iterator.next();
        Assertions.assertEquals("CN=ca-p256ecdsa", cert.getSubjectDN().getName());
        cert = (X509Certificate) iterator.next();
        Assertions.assertEquals( "CN=ca-p256sm2", cert.getSubjectDN().getName());
        cert = (X509Certificate) iterator.next();
        Assertions.assertEquals("CN=ca-sm2sm2", cert.getSubjectDN().getName());
        cert = (X509Certificate) iterator.next();
        Assertions.assertEquals("CN=ca-sm2ecdsa", cert.getSubjectDN().getName());
    }

    @Test
    public void testGetCertPathEncodings() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "KonaPKIX");
        Iterator<String> it = cf.getCertPathEncodings();
        Assertions.assertEquals("PkiPath", it.next());
        Assertions.assertEquals("PKCS7", it.next());
    }

    @Test
    public void testGenCertPath() throws Exception {
        List<X509Certificate> certs = new ArrayList<>();
        certs.add(TestUtils.certAsFile("ca-rsarsa.crt"));
        certs.add(TestUtils.certAsFile("ca-p256ecdsa.crt"));
        certs.add(TestUtils.certAsFile("ca-p256sm2.crt"));
        certs.add(TestUtils.certAsFile("ca-sm2sm2.crt"));
        certs.add(TestUtils.certAsFile("ca-sm2ecdsa.crt"));

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "KonaPKIX");

        CertPath certPath = cf.generateCertPath(certs);
        Assertions.assertEquals(certs.size(), certPath.getCertificates().size());

        byte[] pkiPathEncodedCertPath = certPath.getEncoded("PkiPath");

        CertPath defaultCertPath = cf.generateCertPath(
                new ByteArrayInputStream(pkiPathEncodedCertPath));
        Assertions.assertEquals(certs.size(), defaultCertPath.getCertificates().size());

        CertPath pkiPathCertPath = cf.generateCertPath(
                new ByteArrayInputStream(pkiPathEncodedCertPath), "PkiPath");
        Assertions.assertEquals(certs.size(), pkiPathCertPath.getCertificates().size());

        byte[] pkcs7EncodedCertPath = certPath.getEncoded("PKCS7");
        CertPath pkcs7CertPath = cf.generateCertPath(
                new ByteArrayInputStream(pkcs7EncodedCertPath), "PKCS7");
        Assertions.assertEquals(certs.size(), pkcs7CertPath.getCertificates().size());
    }

    @Test
    public void testGenCRL() throws Exception {
        testGenCRL("intca-p256ecdsa-p256ecdsa.crl",
                AlgorithmId.SHA256withECDSA_oid);
        testGenCRL("intca-sm2sm2-sm2sm2.crl",
                AlgorithmId.SM3withSM2_OID);
    }

    private void testGenCRL(String crlFileName, ObjectIdentifier sigAlgOid)
            throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "KonaPKIX");
        X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(
                TestUtils.crlBytes(crlFileName)));
        Assertions.assertEquals(sigAlgOid.toString(), crl.getSigAlgOID());
    }

    @Test
    public void testGenCRLs() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "KonaPKIX");

        @SuppressWarnings("unchecked")
        List<? extends X509CRL> crls = (List<? extends X509CRL>) cf.generateCRLs(
                new ByteArrayInputStream(TestUtils.concatCertFiles(
                        "intca-p256ecdsa-p256ecdsa.crl",
                        "intca-sm2sm2-sm2sm2.crl").getBytes(
                                StandardCharsets.UTF_8)));
        Assertions.assertEquals(2, crls.size());

        Assertions.assertEquals(
                AlgorithmId.SHA256withECDSA_oid.toString(),
                crls.get(0).getSigAlgOID());
        Assertions.assertEquals(
                AlgorithmId.SM3withSM2_OID.toString(),
                crls.get(1).getSigAlgOID());
    }
}
