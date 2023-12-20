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

package com.tencent.kona.pkix.demo;

import com.tencent.kona.pkix.TestUtils;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
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
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;

/**
 * A comprehensive demo for public key infrastructure implementation.
 */
public class PKIDemo {

    /* The CA certificate.
     *
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             74:7a:13:d4:70:5d:74:07:fd:33:58:4d:8e:6b:da:7d:25:8c:73:a3
     *         Signature Algorithm: sm3WithSM2Sign
     *         Issuer: CN = ca-demo
     *         Validity
     *             Not Before: Dec  1 03:24:15 2021 GMT
     *             Not After : Nov 29 03:24:15 2031 GMT
     *         Subject: CN = ca-demo
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (256 bit)
     *                 pub:
     *                     04:cd:ba:07:1b:e9:60:50:36:66:44:ed:54:be:32:
     *                     0e:78:cd:4d:3b:83:79:be:18:b0:2d:8e:c7:1c:0f:
     *                     47:90:ed:2c:17:a6:33:f8:9c:da:24:6b:1e:98:23:
     *                     32:b9:94:9e:a6:ac:ce:98:d8:65:79:02:f8:da:22:
     *                     65:9b:ba:27:56
     *                 ASN1 OID: SM2
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 7B:23:29:2E:D6:F3:4B:0B:39:C5:05:55:E2:E8:E9:47:3A:DA:32:47
     *             X509v3 Authority Key Identifier:
     *                 keyid:7B:23:29:2E:D6:F3:4B:0B:39:C5:05:55:E2:E8:E9:47:3A:DA:32:47
     *
     *             X509v3 Basic Constraints: critical
     *                 CA:TRUE
     *             X509v3 Key Usage: critical
     *                 Digital Signature, Certificate Sign, CRL Sign
     *             X509v3 Extended Key Usage: critical
     *                 OCSP Signing
     *     Signature Algorithm: sm3WithSM2Sign
     *          30:46:02:21:00:ed:49:c1:18:b8:a1:55:30:60:58:58:31:d2:
     *          92:46:65:a3:5d:c1:65:d2:80:23:10:e3:03:ff:ce:ef:84:d7:
     *          93:02:21:00:ba:62:2f:5d:bb:cd:6e:9d:2b:8c:39:97:bd:82:
     *          b8:07:5a:11:2a:12:c2:cf:55:50:02:a3:9c:0a:17:9c:8a:51
     */
    private static final String CA =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBojCCAUegAwIBAgIUdHoT1HBddAf9M1hNjmvafSWMc6MwCgYIKoEcz1UBg3Uw\n" +
            "EjEQMA4GA1UEAwwHY2EtZGVtbzAeFw0yMTEyMDEwMzI0MTVaFw0zMTExMjkwMzI0\n" +
            "MTVaMBIxEDAOBgNVBAMMB2NhLWRlbW8wWTATBgcqhkjOPQIBBggqgRzPVQGCLQNC\n" +
            "AATNugcb6WBQNmZE7VS+Mg54zU07g3m+GLAtjsccD0eQ7SwXpjP4nNokax6YIzK5\n" +
            "lJ6mrM6Y2GV5AvjaImWbuidWo3sweTAdBgNVHQ4EFgQUeyMpLtbzSws5xQVV4ujp\n" +
            "RzraMkcwHwYDVR0jBBgwFoAUeyMpLtbzSws5xQVV4ujpRzraMkcwDwYDVR0TAQH/\n" +
            "BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwkw\n" +
            "CgYIKoEcz1UBg3UDSQAwRgIhAO1JwRi4oVUwYFhYMdKSRmWjXcFl0oAjEOMD/87v\n" +
            "hNeTAiEAumIvXbvNbp0rjDmXvYK4B1oRKhLCz1VQAqOcChecilE=\n" +
            "-----END CERTIFICATE-----";

    // The CA private key.
    private static final String CA_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgqiXZE9IGb/jccQdf\n" +
            "2WYJNk+KVWk8/pPwWx5giD06FX+hRANCAATNugcb6WBQNmZE7VS+Mg54zU07g3m+\n" +
            "GLAtjsccD0eQ7SwXpjP4nNokax6YIzK5lJ6mrM6Y2GV5AvjaImWbuidW";

    /* The end entity certificate.
     *
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             25:8e:55:7a:3a:8f:f6:9a:0a:24:38:48:6d:a4:9b:eb:b1:4f:2e:88
     *         Signature Algorithm: sm3WithSM2Sign
     *         Issuer: CN = ca-demo
     *         Validity
     *             Not Before: Dec  3 03:39:10 2021 GMT
     *             Not After : Dec  1 03:39:10 2031 GMT
     *         Subject: CN = ee-demo
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (256 bit)
     *                 pub:
     *                     04:92:e3:67:d8:0f:1e:fc:66:4d:d3:f5:ad:33:e5:
     *                     7b:f5:ae:1f:f9:ee:f7:d1:96:f9:2b:96:66:6c:b8:
     *                     de:d5:53:5b:5c:1e:4c:54:a7:38:91:34:d2:41:80:
     *                     7b:e1:41:b4:1b:7c:c7:24:cf:da:0d:40:9e:62:48:
     *                     2c:19:2f:a3:11
     *                 ASN1 OID: SM2
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 98:08:AD:39:87:BF:16:E3:6E:ED:6C:08:04:8A:8E:40:45:8A:97:F7
     *             X509v3 Authority Key Identifier:
     *                 keyid:7B:23:29:2E:D6:F3:4B:0B:39:C5:05:55:E2:E8:E9:47:3A:DA:32:47
     *
     *             X509v3 CRL Distribution Points:
     *
     *                 Full Name:
     *                   URI:file:src/test/resources/demo/ee-demo.crl
     *
     *     Signature Algorithm: sm3WithSM2Sign
     *          30:45:02:20:7b:9d:c2:46:59:b1:f1:3a:1a:40:ca:3b:8a:51:
     *          c2:e6:a6:f8:ca:94:14:28:63:fa:d3:4e:8e:9d:dd:81:11:01:
     *          02:21:00:a2:01:ae:e1:6c:12:e0:4a:54:7c:fb:28:1c:6c:77:
     *          88:6c:8c:3a:d9:7d:67:b5:9f:c7:f3:87:af:69:a7:4c:d2
     */
    private static final String EE =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBozCCAUmgAwIBAgIUJY5VejqP9poKJDhIbaSb67FPLogwCgYIKoEcz1UBg3Uw\n" +
            "EjEQMA4GA1UEAwwHY2EtZGVtbzAeFw0yMTEyMDMwMzM5MTBaFw0zMTEyMDEwMzM5\n" +
            "MTBaMBIxEDAOBgNVBAMMB2VlLWRlbW8wWTATBgcqhkjOPQIBBggqgRzPVQGCLQNC\n" +
            "AASS42fYDx78Zk3T9a0z5Xv1rh/57vfRlvkrlmZsuN7VU1tcHkxUpziRNNJBgHvh\n" +
            "QbQbfMckz9oNQJ5iSCwZL6MRo30wezAdBgNVHQ4EFgQUmAitOYe/FuNu7WwIBIqO\n" +
            "QEWKl/cwHwYDVR0jBBgwFoAUeyMpLtbzSws5xQVV4ujpRzraMkcwOQYDVR0fBDIw\n" +
            "MDAuoCygKoYoZmlsZTpzcmMvdGVzdC9yZXNvdXJjZXMvZGVtby9lZS1kZW1vLmNy\n" +
            "bDAKBggqgRzPVQGDdQNIADBFAiB7ncJGWbHxOhpAyjuKUcLmpvjKlBQoY/rTTo6d\n" +
            "3YERAQIhAKIBruFsEuBKVHz7KBxsd4hsjDrZfWe1n8fzh69pp0zS\n" +
            "-----END CERTIFICATE-----";

    // The end entity private key.
    private static final String EE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKA+GflBSRHU/rjIb\n" +
            "8NSetAkTqaeRwKtkAgkjhoPE63ChRANCAASS42fYDx78Zk3T9a0z5Xv1rh/57vfR\n" +
            "lvkrlmZsuN7VU1tcHkxUpziRNNJBgHvhQbQbfMckz9oNQJ5iSCwZL6MR";

    /* The certificate revocation list, which revokes the above EE certificate.
     *
     * Certificate Revocation List (CRL):
     *         Version 2 (0x1)
     *         Signature Algorithm: sm3WithSM2Sign
     *         Issuer: CN = ca-demo
     *         Last Update: Dec  3 03:45:14 2021 GMT
     *         Next Update: Dec  1 03:45:14 2031 GMT
     * Revoked Certificates:
     *     Serial Number: 258E557A3A8FF69A0A2438486DA49BEBB14F2E88
     *         Revocation Date: Dec  3 03:44:54 2021 GMT
     *         CRL entry extensions:
     *             X509v3 CRL Reason Code:
     *                 Superseded
     *     Signature Algorithm: sm3WithSM2Sign
     *          30:45:02:21:00:c2:4a:5b:d8:6b:1d:44:9b:3f:0f:15:f1:9c:
     *          a9:b3:a7:9c:53:3c:16:8c:be:60:79:e9:ee:53:47:8b:72:6b:
     *          61:02:20:2a:5c:23:a7:4f:5c:a7:00:7c:fa:a6:c0:b4:b5:df:
     *          fc:95:14:7e:ee:cb:a7:61:85:90:ae:2a:11:b3:38:e9:d3
     */
    private static final String CRL =
            "-----BEGIN X509 CRL-----\n" +
            "MIHQMHgCAQEwCgYIKoEcz1UBg3UwEjEQMA4GA1UEAwwHY2EtZGVtbxcNMjExMjAz\n" +
            "MDM0NTE0WhcNMzExMjAxMDM0NTE0WjA1MDMCFCWOVXo6j/aaCiQ4SG2km+uxTy6I\n" +
            "Fw0yMTEyMDMwMzQ0NTRaMAwwCgYDVR0VBAMKAQQwCgYIKoEcz1UBg3UDSAAwRQIh\n" +
            "AMJKW9hrHUSbPw8V8Zyps6ecUzwWjL5geenuU0eLcmthAiAqXCOnT1ynAHz6psC0\n" +
            "td/8lRR+7sunYYWQrioRszjp0w==\n" +
            "-----END X509 CRL-----";

    private static final String PASSWORD = "password";

    @Test
    public void pkiDemo() throws Exception {
        TestUtils.addProviders();

        KeyStore keyStore = createKeyStore(CA, EE, EE_KEY);

        X509Certificate caCert
                = (X509Certificate) keyStore.getCertificate("ca-demo");
        PKIXParameters params = new PKIXParameters(
                Collections.singleton(new TrustAnchor(caCert, null)));
        // Don't check the revocation status.
        params.setRevocationEnabled(false);

        // Create a certificate path with only one EE certificate.
        X509Certificate eeCert
                = (X509Certificate) keyStore.getCertificate("ee-demo");
        CertPath certPath = createCertPath(new X509Certificate[] { eeCert });

        CertPathValidator validator = CertPathValidator.getInstance("PKIX", "KonaPKIX");

        // Validate the cert path with the trusted CA,
        // and not check the revocation status.
        // This time the validation would pass.
        validator.validate(certPath, params);

        // Try to validate the certificate chain again,
        // Require to check the revocation status this time.
        params.setRevocationEnabled(true);

        // Enable CRL Distribution Points (CRLDP) extension,
        // the validator would access the CRL declared by CRLDP.
        // The CRL file, exactly ee-demo.crl, must be at relative path
        // src/test/resources/demo/ee-demo.crl.
        System.setProperty("com.tencent.kona.pkix.enableCRLDP", "true");

        // Validate the cert path with the trusted CA,
        // and check the revocation status.
        // Because the CRL claims the EE certificate is already revoked,
        // hence the validation would fail this time.
        try {
            validator.validate(certPath, params);
        } catch (CertPathValidatorException cpve) {
            if (cpve.getMessage().contains("revoked")) {
                System.out.println("Expected CertPathValidatorException: "
                        + cpve.getMessage());
            } else {
                throw new AssertionError(
                        "Unexpected CertPathValidatorException", cpve);
            }
        }
    }

    // Create a KeyStore with CA and EE certificates
    private static KeyStore createKeyStore(String caStr, String eeStr,
            String eeKeyStr) throws Exception {
        X509Certificate caCert = loadCert(caStr);
        X509Certificate eeCert = loadCert(eeStr);

        // Create a PKCS#12 key store
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "KonaPKIX");
        keyStore.load(null, null);

        // Add the CA as trusted certificate
        keyStore.setCertificateEntry("ca-demo", caCert);

        // Add the EE private key and the associated certificate chain,
        // which contains only one certificate, exactly the EE itself.
        // And it requires to protect the private key based on a password.
        PrivateKey privateKey = loadPrivateKey(eeKeyStr);
        keyStore.setKeyEntry("ee-demo",
                privateKey,
                PASSWORD.toCharArray(),
                new Certificate[] { eeCert } );

        return keyStore;
    }

    // Load a certificate
    private static X509Certificate loadCert(String certPEM) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance(
                "X.509", "KonaPKIX");
        return (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(certPEM.getBytes()));
    }

    // Load a private key
    private static PrivateKey loadPrivateKey(String keyPEM) throws Exception {
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                Base64.getMimeDecoder().decode(keyPEM));
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "KonaCrypto");
        return keyFactory.generatePrivate(privateKeySpec);
    }

    // Create a certificate path from a certificate collection
    private static CertPath createCertPath(X509Certificate[] certChain)
            throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "KonaPKIX");
        return cf.generateCertPath(Arrays.asList(certChain));
    }

    // Load a certificate revocation list
    private static X509CRL loadCrl(String crlPEM) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance(
                "X.509", "KonaPKIX");
        return (X509CRL) certFactory.generateCRL(
                new ByteArrayInputStream(crlPEM.getBytes()));
    }

    // Create a cert store with certificate revocation lists
    private static CertStore createCertStore(Collection<X509CRL> crls)
            throws Exception {
        return CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(crls), "KonaPKIX");
    }
}
