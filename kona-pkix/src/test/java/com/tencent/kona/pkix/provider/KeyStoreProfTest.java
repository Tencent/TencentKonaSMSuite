/*
 * Copyright (C) 2023, THL A29 Limited, a Tencent company. All rights reserved.
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

import com.tencent.kona.pkix.TestUtils;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * The test for profiling keystore operations.
 */
public class KeyStoreProfTest {

    /* The CA certificate.
     *
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             2a:65:af:df:f4:df:83:58:24:68:f3:54:46:d3:4e:d3:f4:a4:8f:09
     *         Signature Algorithm: ecdsa-with-SHA256
     *         Issuer: CN = ca-p256ecdsa
     *         Validity
     *             Not Before: Sep 11 20:15:16 2021 GMT
     *             Not After : Sep  9 20:15:16 2031 GMT
     *         Subject: CN = intca-p256ecdsa-p256ecdsa
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (256 bit)
     *                 pub:
     *                     04:8f:33:4b:bf:05:dd:e0:8e:9e:49:db:f4:25:08:
     *                     ea:d6:b3:ed:85:e0:00:43:e9:57:4d:cd:d7:5c:c5:
     *                     d7:41:0d:d6:36:9f:ed:9c:37:dc:e1:52:28:21:0f:
     *                     68:21:6f:be:65:79:45:5e:7b:43:df:a4:82:84:b7:
     *                     36:a4:7c:92:26
     *                 ASN1 OID: prime256v1
     *                 NIST CURVE: P-256
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 70:14:99:72:81:7F:0B:D1:A9:1E:88:36:D2:E6:48:97:8F:87:B8:55
     *             X509v3 Authority Key Identifier:
     *                 keyid:AE:05:72:65:AA:6F:06:04:93:E7:D7:2F:0E:00:26:1C:58:88:43:CF
     *
     *             X509v3 Basic Constraints: critical
     *                 CA:TRUE
     *             X509v3 Key Usage: critical
     *                 Digital Signature, Certificate Sign, CRL Sign
     *             X509v3 Extended Key Usage: critical
     *                 OCSP Signing
     *     Signature Algorithm: ecdsa-with-SHA256
     *          30:46:02:21:00:b7:a5:fe:b4:21:dd:a0:50:09:e2:a4:b0:08:
     *          66:77:63:d4:22:1e:d2:b2:e1:b2:91:84:c7:45:a5:9c:40:21:
     *          62:02:21:00:9e:e2:51:f8:e6:24:81:f7:72:43:43:ab:90:6e:
     *          38:df:76:34:a1:b9:65:2f:39:a0:bc:7a:00:73:22:91:5a:15
     */
    private static final String CA =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBuTCCAV6gAwIBAgIUKmWv3/Tfg1gkaPNURtNO0/SkjwkwCgYIKoZIzj0EAwIw\n" +
            "FzEVMBMGA1UEAwwMY2EtcDI1NmVjZHNhMB4XDTIxMDkxMTIwMTUxNloXDTMxMDkw\n" +
            "OTIwMTUxNlowJDEiMCAGA1UEAwwZaW50Y2EtcDI1NmVjZHNhLXAyNTZlY2RzYTBZ\n" +
            "MBMGByqGSM49AgEGCCqGSM49AwEHA0IABI8zS78F3eCOnknb9CUI6taz7YXgAEPp\n" +
            "V03N11zF10EN1jaf7Zw33OFSKCEPaCFvvmV5RV57Q9+kgoS3NqR8kiajezB5MB0G\n" +
            "A1UdDgQWBBRwFJlygX8L0akeiDbS5kiXj4e4VTAfBgNVHSMEGDAWgBSuBXJlqm8G\n" +
            "BJPn1y8OACYcWIhDzzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAW\n" +
            "BgNVHSUBAf8EDDAKBggrBgEFBQcDCTAKBggqhkjOPQQDAgNJADBGAiEAt6X+tCHd\n" +
            "oFAJ4qSwCGZ3Y9QiHtKy4bKRhMdFpZxAIWICIQCe4lH45iSB93JDQ6uQbjjfdjSh\n" +
            "uWUvOaC8egBzIpFaFQ==\n" +
            "-----END CERTIFICATE-----";

    // The CA private key.
    private static final String CA_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfB8dxO/rB3tli7WF\n" +
            "gu3ABwd06ZkHwMsyhoYCHlornOChRANCAASPM0u/Bd3gjp5J2/QlCOrWs+2F4ABD\n" +
            "6VdNzddcxddBDdY2n+2cN9zhUighD2ghb75leUVee0PfpIKEtzakfJIm";

    /* The end entity certificate.
     *
     *  Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             7c:c6:ef:c9:ff:1b:40:4a:4c:11:85:e7:14:db:82:6c:61:57:31:25
     *         Signature Algorithm: ecdsa-with-SHA256
     *         Issuer: CN = intca-p256ecdsa-p256ecdsa
     *         Validity
     *             Not Before: Sep 11 20:15:16 2021 GMT
     *             Not After : Sep  9 20:15:16 2031 GMT
     *         Subject: CN = ee-p256ecdsa-p256ecdsa-p256ecdsa
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (256 bit)
     *                 pub:
     *                     04:b5:f8:d1:d3:03:42:46:59:54:52:4d:6c:1a:91:
     *                     ac:ae:23:84:24:10:ad:58:a8:c2:80:3a:f8:14:0f:
     *                     05:e0:a9:98:19:51:0e:29:e2:7d:d1:e2:5c:6e:03:
     *                     5a:d1:3d:5e:c8:91:44:08:6c:3f:0e:4a:57:38:d6:
     *                     de:8c:3f:41:73
     *                 ASN1 OID: prime256v1
     *                 NIST CURVE: P-256
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 F2:D6:5E:A3:92:8E:78:D1:C0:EE:CB:AA:82:D2:68:68:3E:A0:C8:60
     *             X509v3 Authority Key Identifier:
     *                 keyid:70:14:99:72:81:7F:0B:D1:A9:1E:88:36:D2:E6:48:97:8F:87:B8:55
     *
     *     Signature Algorithm: ecdsa-with-SHA256
     *          30:45:02:21:00:83:0d:30:d2:a4:74:9d:7d:d0:b6:4a:45:30:
     *          5c:3b:ee:82:55:b9:76:61:8f:ac:55:64:e8:97:0d:74:25:08:
     *          72:02:20:63:06:c6:9f:b3:15:8a:34:fb:83:9a:94:75:71:7f:
     *          62:c5:04:16:c4:d9:6a:07:bb:7c:09:6d:67:b0:1c:01:15
     */
    private static final String EE =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBkzCCATmgAwIBAgIUfMbvyf8bQEpMEYXnFNuCbGFXMSUwCgYIKoZIzj0EAwIw\n" +
            "JDEiMCAGA1UEAwwZaW50Y2EtcDI1NmVjZHNhLXAyNTZlY2RzYTAeFw0yMTA5MTEy\n" +
            "MDE1MTZaFw0zMTA5MDkyMDE1MTZaMCsxKTAnBgNVBAMMIGVlLXAyNTZlY2RzYS1w\n" +
            "MjU2ZWNkc2EtcDI1NmVjZHNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtfjR\n" +
            "0wNCRllUUk1sGpGsriOEJBCtWKjCgDr4FA8F4KmYGVEOKeJ90eJcbgNa0T1eyJFE\n" +
            "CGw/DkpXONbejD9Bc6NCMEAwHQYDVR0OBBYEFPLWXqOSjnjRwO7LqoLSaGg+oMhg\n" +
            "MB8GA1UdIwQYMBaAFHAUmXKBfwvRqR6INtLmSJePh7hVMAoGCCqGSM49BAMCA0gA\n" +
            "MEUCIQCDDTDSpHSdfdC2SkUwXDvuglW5dmGPrFVk6JcNdCUIcgIgYwbGn7MVijT7\n" +
            "g5qUdXF/YsUEFsTZage7fAltZ7AcARU=\n" +
            "-----END CERTIFICATE-----";

    // The end entity private key.
    private static final String EE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZY/ebcIPzj+r0Jf7\n" +
            "xiH0qu5fsCLlkGTlgnMBuaDQqOahRANCAAS1+NHTA0JGWVRSTWwakayuI4QkEK1Y\n" +
            "qMKAOvgUDwXgqZgZUQ4p4n3R4lxuA1rRPV7IkUQIbD8OSlc41t6MP0Fz";

    private static final char[] PASSWORD = "password".toCharArray();
    private static final KeyStore.PasswordProtection PROTECTION
            = new KeyStore.PasswordProtection(PASSWORD);

    static {
        TestUtils.addProviders();
    }

    public static void main(String[] args) throws Exception {
        KeyStore keyStore = createKeyStore("PKCS12", "KonaPKIX");

        KeyStore.Entry entry = null;
        for (int i = 0; i < 1000; i++) {
            entry = keyStore.getEntry("ee", PROTECTION);
        }
    }

    private static KeyStore createKeyStore(String type, String provider)
            throws Exception {
        KeyStore keyStore;
        if (provider == null) {
            keyStore = KeyStore.getInstance(type);
        } else {
            keyStore = KeyStore.getInstance(type, provider);
        }
        keyStore.load(null, null);

        keyStore.setCertificateEntry("ca", loadCert(CA));

        keyStore.setKeyEntry("ee",
                loadPrivateKey(EE_KEY),
                PASSWORD,
                new Certificate[] { loadCert(EE) } );

        return keyStore;
    }

    // Load a certificate
    private static X509Certificate loadCert(String certPEM) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(certPEM.getBytes()));
    }

    // Load a private key
    private static PrivateKey loadPrivateKey(String keyPEM) throws Exception {
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                Base64.getMimeDecoder().decode(keyPEM));
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(privateKeySpec);
    }

    // Create a certificate path from a certificate collection
    private static CertPath createCertPath(X509Certificate[] certChain)
            throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return cf.generateCertPath(Arrays.asList(certChain));
    }
}
