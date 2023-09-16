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

package com.tencent.kona.pkix.util;

import com.tencent.kona.crypto.spec.SM2ParameterSpec;
import com.tencent.kona.pkix.PKIXUtils;
import com.tencent.kona.pkix.TestUtils;
import com.tencent.kona.sun.security.util.KnownOIDs;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

import static com.tencent.kona.crypto.CryptoUtils.toBigInt;

/**
 * The test for Utils.
 */
public class PKIXUtilsTest {

    private static final String EC_PARAMS =
            "-----BEGIN EC PARAMETERS-----\n" +
            "BggqgRzPVQGCLQ==\n" +
            "-----END EC PARAMETERS-----";

    private static final String EC_PARAMS_WITHOUT_BE =
            "BggqgRzPVQGCLQ==";

    /* ***** PKCS#8 Private Key ***** */

    private static final String PRIVATE_KEY =
            "-----BEGIN PRIVATE KEY-----\n" +
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgqiXZE9IGb/jccQdf\n" +
            "2WYJNk+KVWk8/pPwWx5giD06FX+hRANCAATNugcb6WBQNmZE7VS+Mg54zU07g3m+\n" +
            "GLAtjsccD0eQ7SwXpjP4nNokax6YIzK5lJ6mrM6Y2GV5AvjaImWbuidW\n" +
            "-----END PRIVATE KEY-----";

    private static final String PRIVATE_KEY_WITHOUT_BE =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgqiXZE9IGb/jccQdf\n" +
            "2WYJNk+KVWk8/pPwWx5giD06FX+hRANCAATNugcb6WBQNmZE7VS+Mg54zU07g3m+\n" +
            "GLAtjsccD0eQ7SwXpjP4nNokax6YIzK5lJ6mrM6Y2GV5AvjaImWbuidW";

    /* ***** RFC 5915 Private Key ***** */

    private static final String RFC5915_KEY =
            "-----BEGIN EC PRIVATE KEY-----\n" +
            "MHcCAQEEINAwndUYWVaX1N9MRoYmn+5f+Wvl7EmOz6yHnRkHsWPFoAoGCCqBHM9V\n" +
            "AYItoUQDQgAEEd8Dsf32cEr/jHWYN8EgGHCFh5qu8AyTpdscNUvtx5H1D1mW8kJa\n" +
            "lvIpfGjy54xSg5RS6taPjDKqfEK89CJUqQ==\n" +
            "-----END EC PRIVATE KEY-----";

    private static final String RFC5915_KEY_WITHOUT_BE =
            "MHcCAQEEINAwndUYWVaX1N9MRoYmn+5f+Wvl7EmOz6yHnRkHsWPFoAoGCCqBHM9V\n" +
            "AYItoUQDQgAEEd8Dsf32cEr/jHWYN8EgGHCFh5qu8AyTpdscNUvtx5H1D1mW8kJa\n" +
            "lvIpfGjy54xSg5RS6taPjDKqfEK89CJUqQ==";

    /* ***** X.509 Public Key ***** */

    private static final String PUBLIC_KEY =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE8BHoyDr91ptaoN0QRxvYElxdgxzI\n" +
            "WBTynLUqHouCbT2WD03776IFiEWSi1RdmIq7VvE7f8rpvwosDc/timPkcg==\n" +
            "-----END PUBLIC KEY-----";

    private static final String PUBLIC_KEY_WITHOUT_BE =
            "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE8BHoyDr91ptaoN0QRxvYElxdgxzI\n" +
            "WBTynLUqHouCbT2WD03776IFiEWSi1RdmIq7VvE7f8rpvwosDc/timPkcg==";

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
    private static final String CERT =
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

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testGetNamedCurveId() throws Exception {
        testGetNamedCurveId(EC_PARAMS);
        testGetNamedCurveId(EC_PARAMS_WITHOUT_BE);
    }

    private void testGetNamedCurveId(String ecParams) throws Exception {
        String namedCurveId = PKIXUtils.getNamedCurveId(ecParams);
        Assertions.assertEquals(namedCurveId, KnownOIDs.curveSM2.value());
    }

    @Test
    public void testGetPrivateKey() throws Exception {
        testGetPrivateKey(PRIVATE_KEY);
        testGetPrivateKey(PRIVATE_KEY_WITHOUT_BE);
    }

    @Test
    public void testGetPrivateKeyWithoutBELines() throws Exception {
        testGetPrivateKey(PRIVATE_KEY_WITHOUT_BE);
    }

    private void testGetPrivateKey(String keyStr) throws Exception {
        ECPrivateKey key = (ECPrivateKey) PKIXUtils.getPrivateKey("EC", keyStr);
        Assertions.assertEquals(key.getAlgorithm(), "EC");
    }

    @Test
    public void testGetRFC5915PrivateKey() throws Exception {
        testGetRFC5915PrivateKey(RFC5915_KEY);
        testGetRFC5915PrivateKey(RFC5915_KEY_WITHOUT_BE);
    }

    private void testGetRFC5915PrivateKey(String privateKey) throws Exception {
        ECPrivateKey key = (ECPrivateKey) PKIXUtils.getRFC5915PrivateKey(
                privateKey);
        Assertions.assertEquals(key.getAlgorithm(), "EC");
        Assertions.assertEquals(
                SM2ParameterSpec.instance().getCurve(),
                key.getParams().getCurve());
        Assertions.assertEquals(
                toBigInt("D0309DD518595697D4DF4C4686269FEE5FF96BE5EC498ECFAC879D1907B163C5"),
                key.getS());
    }

    @Test
    public void testEncodeRFC5915PrivateKey() throws Exception {
        ECPrivateKey key = (ECPrivateKey) PKIXUtils.getRFC5915PrivateKey(
                RFC5915_KEY);
        byte[] encodedKey = key.getEncoded();
        Assertions.assertArrayEquals(
                Base64.getMimeDecoder().decode(RFC5915_KEY_WITHOUT_BE),
                encodedKey);
    }

    @Test
    public void testGetPublicKey() throws Exception {
        testGetPublicKey(PUBLIC_KEY);
        testGetPublicKey(PUBLIC_KEY_WITHOUT_BE);
    }

    private void testGetPublicKey(String publicKeyStr) throws Exception {
        ECPublicKey key = (ECPublicKey) PKIXUtils.getPublicKey(
                "EC", publicKeyStr);
        Assertions.assertEquals(key.getAlgorithm(), "EC");
    }

    @Test
    public void testGetPublicKeyFromCert() throws Exception {
        ECPublicKey key = (ECPublicKey) PKIXUtils.getPublicKey(CERT);
        Assertions.assertEquals(key.getAlgorithm(), "EC");
    }

    @Test
    public void testGetCertificate() throws Exception {
        X509Certificate cert = PKIXUtils.getCertificate(CERT);
        Assertions.assertEquals(cert.getSigAlgName(), "SM3withSM2");
    }
}
