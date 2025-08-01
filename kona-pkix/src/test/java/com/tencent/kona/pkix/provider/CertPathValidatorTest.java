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
import com.tencent.kona.pkix.SimpleOCSPServer;
import com.tencent.kona.sun.security.x509.SMCertificate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * The test for CertPathValidator.
 */
public class CertPathValidatorTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @BeforeEach
    public void beforeEach() {
        System.clearProperty("com.tencent.kona.pkix.enableCRLDP");
        System.clearProperty("ocsp.enable");
    }

    @Test
    public void testGetCertPathValidator() throws Exception {
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "KonaPKIX");
        Assertions.assertTrue(cpv.getProvider() instanceof KonaPKIXProvider);
    }

    @Test
    public void testValidateSingleCert() throws Exception {
        validate(
                new String[] { "ca-rsarsa.crt" },
                new String[] { "ca-rsarsa.crt" });
        validate(
                new String[] { "ca-p256ecdsa.crt" },
                new String[] { "ca-p256ecdsa.crt" });
        validate(
                new String[] { "ca-sm2sm2.crt" },
                new String[] { "ca-sm2sm2.crt" });

        // May not support the below scenarios, because it looks not reasonable
        // that the public key and signature algorithms are not compatible in a
        // single self-signed certificate. For example, the public key is EC
        // with curve SECP256R1 and the signature scheme is SM3withSM2.
//        testValidate(
//                new String[] { "ca-p256sm2.crt" },
//                new String[] { "ca-p256sm2.crt" });
//        testValidate(
//                new String[] { "ca-sm2ecdsa.crt" },
//                new String[] { "ca-sm2ecdsa.crt" });

        validate(
                new String[] { "intca-p256ecdsa-p256ecdsa.crt" },
                new String[] { "ca-p256ecdsa.crt" });
        validate(
                new String[] { "intca-p256ecdsa-p256sm2.crt" },
                new String[] { "ca-p256sm2.crt" });
        validate(
                new String[] { "intca-p256sm2-sm2ecdsa.crt" },
                new String[] { "ca-sm2ecdsa.crt" });
        validate(
                new String[] { "intca-sm2ecdsa-p256ecdsa.crt" },
                new String[] { "ca-p256ecdsa.crt" });
        validate(
                new String[] { "intca-sm2sm2-sm2sm2.crt" },
                new String[] { "ca-sm2sm2.crt" });

        validate(
                new String[] { "ee-p256ecdsa-p256ecdsa-p256ecdsa.crt" },
                new String[] { "intca-p256ecdsa-p256ecdsa.crt" });
        validate(
                new String[] { "ee-p256ecdsa-p256ecdsa-p256sm2.crt" },
                new String[] { "intca-p256ecdsa-p256sm2.crt" });
        validate(
                new String[] { "ee-p256ecdsa-p256sm2-sm2ecdsa.crt" },
                new String[] { "intca-p256sm2-sm2ecdsa.crt" });
        validate(
                new String[] { "ee-p256sm2-sm2ecdsa-p256ecdsa.crt" },
                new String[] { "intca-sm2ecdsa-p256ecdsa.crt" });
        validate(
                new String[] { "ee-sm2ecdsa-p256ecdsa-p256ecdsa.crt" },
                new String[] { "intca-p256ecdsa-p256ecdsa.crt" });
        validate(
                new String[] { "ee-sm2sm2-sm2ecdsa-p256ecdsa.crt" },
                new String[] { "intca-sm2ecdsa-p256ecdsa.crt" });
        validate(
                new String[] { "ee-sm2sm2-sm2sm2-sm2sm2.crt" },
                new String[] { "intca-sm2sm2-sm2sm2.crt" });
    }

    @Test
    public void testValidateCertChain() throws Exception {
        validate(
                new String[] {
                        "ee-rsarsa-rsarsa-rsarsa.crt",
                        "intca-rsarsa-rsarsa.crt" },
                new String[] { "ca-rsarsa.crt" });
        validate(
                new String[] {
                        "ee-p256ecdsa-p256ecdsa-p256ecdsa.crt",
                        "intca-p256ecdsa-p256ecdsa.crt" },
                new String[] { "ca-p256ecdsa.crt" });
        validate(
                new String[] {
                        "ee-p256ecdsa-p256ecdsa-p256sm2.crt",
                        "intca-p256ecdsa-p256sm2.crt" },
                new String[] { "ca-p256sm2.crt" });
        validate(
                new String[] {
                        "ee-p256ecdsa-p256sm2-sm2ecdsa.crt",
                        "intca-p256sm2-sm2ecdsa.crt" },
                new String[] { "ca-sm2ecdsa.crt" });
        validate(
                new String[] {
                        "ee-p256sm2-sm2ecdsa-p256ecdsa.crt",
                        "intca-sm2ecdsa-p256ecdsa.crt" },
                new String[] { "ca-p256ecdsa.crt" });
        validate(
                new String[] {
                        "ee-sm2ecdsa-p256ecdsa-p256ecdsa.crt",
                        "intca-p256ecdsa-p256ecdsa.crt" },
                new String[] { "ca-p256ecdsa.crt" });
        validate(
                new String[] {
                        "ee-sm2sm2-sm2ecdsa-p256ecdsa.crt",
                        "intca-sm2ecdsa-p256ecdsa.crt" },
                new String[] { "ca-p256ecdsa.crt" });
        validate(
                new String[] {
                        "ee-sm2sm2-sm2sm2-sm2sm2.crt",
                        "intca-sm2sm2-sm2sm2.crt" },
                new String[] { "ca-sm2sm2.crt" });
    }

    @Test
    public void testValidateCertChainFailed() throws Exception {
        validate(
                new String[] {
                        "ee-rsarsa-rsarsa-rsarsa.crt",
                        "intca-sm2ecdsa-p256ecdsa.crt" }, // Broken
                new String[] { "ca-rsarsa.crt" },
                false,
                CertPathValidatorException.class);
        validate(
                new String[] {
                        "ee-p256ecdsa-p256ecdsa-p256ecdsa.crt",
                        "intca-sm2ecdsa-p256ecdsa.crt" }, // Broken
                new String[] { "ca-p256ecdsa.crt" },
                false,
                CertPathValidatorException.class);
        validate(
                new String[] {
                        "ee-p256ecdsa-p256ecdsa-p256ecdsa.crt",
                        "intca-p256ecdsa-p256ecdsa.crt" },
                new String[] { "ca-sm2sm2.crt" }, // Broken
                false,
                CertPathValidatorException.class);
        validate(
                new String[] {
                        "ee-sm2sm2-sm2sm2-sm2sm2.crt",
                        "intca-sm2ecdsa-p256ecdsa.crt" }, // Broken
                new String[] { "ca-sm2sm2.crt" },
                false,
                CertPathValidatorException.class);
        validate(
                new String[] {
                        "ee-sm2sm2-sm2sm2-sm2sm2.crt",
                        "intca-sm2sm2-sm2sm2.crt" },
                new String[] { "ca-p256ecdsa.crt" }, // Broken
                false,
                CertPathValidatorException.class);
    }

    @Test
    public void testValidateCertChainWithCrl() throws Exception {
        validateWithCrl(
                new String[] { "ee-p256ecdsa-p256ecdsa-p256ecdsa.crt" }, // Revoked
                new String[] { "intca-p256ecdsa-p256ecdsa.crt" },
                new String[] { "ee-p256ecdsa-p256ecdsa-p256ecdsa.crl" },
                true,
                CertPathValidatorException.class);
        validateWithCrl(
                new String[] { "ee-sm2sm2-sm2sm2-sm2sm2.crt" }, // Revoked
                new String[] { "intca-sm2sm2-sm2sm2.crt" },
                new String[] { "ee-sm2sm2-sm2sm2-sm2sm2.crl" },
                true,
                CertPathValidatorException.class);

        validateWithCrl(
                new String[] {
                        "ee-p256ecdsa-p256ecdsa-p256ecdsa.crt",
                        "intca-p256ecdsa-p256ecdsa.crt" }, // Revoked
                new String[] { "ca-p256ecdsa.crt" },
                new String[] { "intca-p256ecdsa-p256ecdsa.crl" },
                true,
                CertPathValidatorException.class);
        validateWithCrl(
                new String[] {
                        "ee-sm2sm2-sm2sm2-sm2sm2.crt",
                        "intca-sm2sm2-sm2sm2.crt" }, // Revoked
                new String[] { "ca-sm2sm2.crt" },
                new String[] { "intca-sm2sm2-sm2sm2.crl" },
                true,
                CertPathValidatorException.class);
    }

    @Test
    public void testValidateCertChainWithCrldp() throws Exception {
        System.setProperty("com.tencent.kona.pkix.enableCRLDP", "true");

        validateWithCrl(
                // Revoked by ee-p256ecdsa-p256ecdsa-p256ecdsa-crldp.crl
                new String[] { "ee-p256ecdsa-p256ecdsa-p256ecdsa-crldp.crt" },
                new String[] { "intca-p256ecdsa-p256ecdsa.crt" },
                new String[] { "ca-p256ecdsa-empty.crl" },
                true,
                CertPathValidatorException.class);
        validateWithCrl(
                // Revoked by ee-sm2sm2-sm2sm2-sm2sm2-crldp.crl
                new String[] { "ee-sm2sm2-sm2sm2-sm2sm2-crldp.crt" },
                new String[] { "intca-sm2sm2-sm2sm2.crt" },
                new String[] { "ca-sm2sm2-empty.crl" },
                true,
                CertPathValidatorException.class);
    }

    @Test
    public void testValidateCertChainWithOcsp() throws Exception {
        Security.setProperty("ocsp.enable", "true");

        testValidateCertChainWithOcsp(
                "intca-p256ecdsa-p256ecdsa.crt",
                "intca-p256ecdsa-p256ecdsa.key",
                "ee-p256ecdsa-p256ecdsa-p256ecdsa-aia.crt",
                SimpleOCSPServer.CertStatus.CERT_STATUS_GOOD);
        testValidateCertChainWithOcsp(
                "intca-p256ecdsa-p256ecdsa.crt",
                "intca-p256ecdsa-p256ecdsa.key",
                "ee-p256ecdsa-p256ecdsa-p256ecdsa-aia.crt",
                SimpleOCSPServer.CertStatus.CERT_STATUS_REVOKED,
                CertPathValidatorException.class);

        testValidateCertChainWithOcsp(
                "intca-sm2sm2-sm2sm2.crt",
                "intca-sm2sm2-sm2sm2.key",
                "ee-sm2sm2-sm2sm2-sm2sm2-aia.crt",
                SimpleOCSPServer.CertStatus.CERT_STATUS_GOOD);
        testValidateCertChainWithOcsp(
                "intca-sm2sm2-sm2sm2.crt",
                "intca-sm2sm2-sm2sm2.key",
                "ee-sm2sm2-sm2sm2-sm2sm2-aia.crt",
                SimpleOCSPServer.CertStatus.CERT_STATUS_REVOKED,
                CertPathValidatorException.class);
    }

    private void testValidateCertChainWithOcsp(String issuerCertName,
            String issuerKeyName, String certName,
            SimpleOCSPServer.CertStatus certStatus,
            Class<? extends Exception> expectedEx) throws Exception {
        SimpleOCSPServer ocspServer = createOCSPServer(
                issuerCertName, issuerKeyName);
        ocspServer.start();
        if (!ocspServer.awaitServerReady(5, TimeUnit.SECONDS)) {
            throw new RuntimeException("OCSP server is not started");
        }

        X509Certificate eeCert = TestUtils.certAsFile(certName);
        Map<BigInteger, SimpleOCSPServer.CertStatusInfo> certStatusInfos
                = Collections.singletonMap(
                        eeCert.getSerialNumber(),
                        new SimpleOCSPServer.CertStatusInfo(certStatus));
        ocspServer.updateStatusDb(certStatusInfos);

        // Not use the static OCSP URL defined by AIA extension in the
        // certificate, instead, just use the real OCSP responder URL.
        Security.setProperty("ocsp.responderURL",
                "http://127.0.0.1:" + ocspServer.getPort());
        validate(
                new String[] { certName },
                null,
                new String[] { issuerCertName },
                true,
                expectedEx);
    }

    private void testValidateCertChainWithOcsp(String issuerCertName,
            String issuerKeyName, String certName,
            SimpleOCSPServer.CertStatus certStatus) throws Exception {
        testValidateCertChainWithOcsp(
                issuerCertName, issuerKeyName, certName, certStatus, null);
    }

    @Test
    public void testCustomId() throws Exception {
        validate(
                new String[] { "ee-sm2sm2-sm2sm2-sm2sm2-id.crt" },
                new String[] { "custom-id" },
                new String[] { "intca-sm2sm2-sm2sm2.crt" });

        // SH256withECDSA is not affected by the incorrect ID
        validate(
                new String[] { "ca-p256ecdsa.crt" },
                null,
                new String[] { "ca-p256ecdsa.crt" });

        // SM3withSM2 is affected by the incorrect ID
        validate(
                new String[] { "ca-sm2sm2-foo.crt" },
                new String[] { "12345678" },
                new String[] { "ca-sm2sm2-foo.crt" },
                false,
                CertPathValidatorException.class);

        validate(
                new String[] { "intca-p256ecdsa-p256ecdsa.crt" },
                null,
                new String[] { "ca-p256ecdsa.crt" });

        validate(
                new String[] { "ca-sm2sm2-bar.crt" },
                new String[] { "1234567812345678" },
                new String[] { "ca-sm2sm2-bar.crt" });
    }

    private void validate(String[] certChain, String[] ids, String[] cas)
            throws Exception {
        validate(certChain, ids, cas, false, null);
    }

    private void validate(String[] certChain, String[] cas)
            throws Exception {
        validate(certChain, null, cas, false, null);
    }

    private void validate(String[] certChain, String[] ids, String[] cas,
            boolean checkCertStatus, Class<? extends Exception> expectedEx)
            throws Exception {
        validateWithCrl(certChain, ids, cas, null, checkCertStatus, expectedEx);
    }

    private void validate(String[] certChain, String[] cas,
            boolean checkCertStatus, Class<? extends Exception> expectedEx)
            throws Exception {
        validate(certChain, null, cas, checkCertStatus, expectedEx);
    }

    private void validateWithCrl(String[] certChain, String[] cas,
            String[] crls, boolean checkCertStatus,
            Class<? extends Exception> expectedEx) throws Exception {
        validateWithCrl(certChain, null, cas, crls, checkCertStatus, expectedEx);
    }

    private void validateWithCrl(String[] certChain, String[] ids,
            String[] cas, String[] crls, boolean checkCertStatus,
            Class<? extends Exception> expectedEx) throws Exception {
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", "KonaPKIX");
        try {
            cpv.validate(certPath(certChain, ids), certPathParams(
                    cas, crls, checkCertStatus));
            if (expectedEx != null) {
                throw new RuntimeException(
                        "Expected " + expectedEx + " was not thrown");
            }
        } catch (Exception ex) {
            if (expectedEx != null && expectedEx.isInstance(ex)) {
                System.out.printf("Expected %s: %s%n",
                        expectedEx.getSimpleName(), ex.getMessage());
            } else {
                throw ex;
            }
        }
    }

    private CertPath certPath(String[] certChain, String[] ids)
            throws Exception {
        List<X509Certificate> certs = new ArrayList<>();

        for (int i = 0; i < certChain.length; i++) {
            X509Certificate x509Cert = TestUtils.certAsFile(certChain[i]);
            if (ids != null) {
                ((SMCertificate) x509Cert).setId(
                        ids[i].getBytes(StandardCharsets.UTF_8));
            }
            certs.add(x509Cert);
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "KonaPKIX");;
        return cf.generateCertPath(certs);
    }

    private PKIXParameters certPathParams(String[] cas, boolean checkCertStatus)
            throws Exception {
        Set<TrustAnchor> anchors = new LinkedHashSet<>();
        for (String ca : cas) {
            anchors.add(new TrustAnchor(TestUtils.certAsFile(ca), null));
        }

        PKIXParameters params = new PKIXParameters(anchors);
        params.setRevocationEnabled(checkCertStatus);
        return params;
    }

    private PKIXParameters certPathParams(String[] cas, String[] crls,
            boolean checkCertStatus) throws Exception {
        PKIXParameters params = certPathParams(cas, checkCertStatus);

        if (crls != null) {
            Set<X509CRL> x509Crls = new LinkedHashSet<>();
            for (String crl : crls) {
                x509Crls.add(TestUtils.crlAsFile(crl));
            }
            CertStore certStore = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(x509Crls), "KonaPKIX");
            params.addCertStore(certStore);
        }

        return params;
    }

    private SimpleOCSPServer createOCSPServer(
            String issuerCertName, String issuerKeyName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "KonaPKIX");
        keyStore.load(null, null);

        String password = "password";
        String alias = "issuer";
        X509Certificate signerCert = TestUtils.certAsFile(issuerCertName);
        ECPrivateKey signerKey = TestUtils.ecPrivateKeyAsFile(issuerKeyName);
        keyStore.setKeyEntry(alias, signerKey, password.toCharArray(),
                new Certificate[] { signerCert });

        SimpleOCSPServer ocspServer = new SimpleOCSPServer(
                InetAddress.getLoopbackAddress(), 0,
                keyStore, password, alias, null);
        ocspServer.setNextUpdateInterval(3600);
        return ocspServer;
    }
}
