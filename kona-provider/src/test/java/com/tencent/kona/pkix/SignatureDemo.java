/*
 * Copyright (C) 2022, 2024, THL A29 Limited, a Tencent company. All rights reserved.
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

package com.tencent.kona.pkix;

import com.tencent.kona.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class SignatureDemo {

    /*
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             0f:4e:f3:42:d2:38:07:ed:7f:70:aa:c3:e9:01:c8:b6:6e:36:c6:2a
     *         Signature Algorithm: sm3WithSM2Sign
     *         Issuer: CN = intca-sm2sm2-sm2sm2
     *         Validity
     *             Not Before: Sep 11 20:15:16 2021 GMT
     *             Not After : Sep  9 20:15:16 2031 GMT
     *         Subject: CN = ee-sm2sm2-sm2sm2-sm2sm2
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (256 bit)
     *                 pub:
     *                     04:7b:9a:74:83:de:13:93:f7:7f:e3:30:44:79:97:
     *                     f1:2e:97:4e:d9:70:2b:ee:fd:83:35:a4:c3:85:8b:
     *                     53:3f:3a:a9:eb:cb:37:52:ea:38:51:a4:18:a4:96:
     *                     53:00:48:e6:0b:73:d7:8d:ce:30:4e:51:28:f6:3e:
     *                     f8:d3:83:00:e4
     *                 ASN1 OID: SM2
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 D0:BD:67:9E:17:06:7C:B9:4D:89:59:D3:D5:6F:14:AD:26:5D:8E:70
     *             X509v3 Authority Key Identifier:
     *                 keyid:BD:AA:64:6D:4D:40:33:81:B7:50:B3:4D:2F:12:7D:8E:A6:EF:64:42
     *
     *     Signature Algorithm: sm3WithSM2Sign
     *          30:44:02:20:5e:8c:85:a5:29:06:25:06:7a:12:cf:b7:51:7c:
     *          fe:c3:c0:fc:3d:7d:c0:75:e8:ce:7e:9c:18:aa:f4:39:d8:d9:
     *          02:20:0a:ba:a5:ae:d7:34:f0:c0:b0:84:bd:ce:91:a0:23:dd:
     *          c4:2f:cc:f0:95:21:ee:da:37:15:2e:18:f4:38:2c:86
     */
    private static final String CERT =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBgzCCASqgAwIBAgIUD07zQtI4B+1/cKrD6QHItm42xiowCgYIKoEcz1UBg3Uw\n" +
            "HjEcMBoGA1UEAwwTaW50Y2Etc20yc20yLXNtMnNtMjAeFw0yMTA5MTEyMDE1MTZa\n" +
            "Fw0zMTA5MDkyMDE1MTZaMCIxIDAeBgNVBAMMF2VlLXNtMnNtMi1zbTJzbTItc20y\n" +
            "c20yMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEe5p0g94Tk/d/4zBEeZfxLpdO\n" +
            "2XAr7v2DNaTDhYtTPzqp68s3Uuo4UaQYpJZTAEjmC3PXjc4wTlEo9j7404MA5KNC\n" +
            "MEAwHQYDVR0OBBYEFNC9Z54XBny5TYlZ09VvFK0mXY5wMB8GA1UdIwQYMBaAFL2q\n" +
            "ZG1NQDOBt1CzTS8SfY6m72RCMAoGCCqBHM9VAYN1A0cAMEQCIF6MhaUpBiUGehLP\n" +
            "t1F8/sPA/D19wHXozn6cGKr0OdjZAiAKuqWu1zTwwLCEvc6RoCPdxC/M8JUh7to3\n" +
            "FS4Y9Dgshg==\n" +
            "-----END CERTIFICATE-----";

    // PKCS#8 private key
    private static final String KEY =
            "-----BEGIN PRIVATE KEY-----\n" +
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgcl+HTIB9ylaqVCDS\n" +
            "F76T0zPnTZ7QI9SIBlw7ZU+GYb2hRANCAAR7mnSD3hOT93/jMER5l/Eul07ZcCvu\n" +
            "/YM1pMOFi1M/OqnryzdS6jhRpBikllMASOYLc9eNzjBOUSj2PvjTgwDk\n" +
            "-----END PRIVATE KEY-----";

    private static final byte[] DATA = "MESSAGE".getBytes(StandardCharsets.UTF_8);

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    // This test uses only JDK APIs.
    @Test
    public void testSignature() throws Exception {
        PrivateKey privateKey = privateKey(KEY);
        Signature signer = Signature.getInstance("SM3withSM2", "Kona");
        signer.initSign(privateKey);
        signer.update(DATA);
        byte[] sign = signer.sign();

        Certificate certificate = certificate(CERT);
        Signature verifier = Signature.getInstance("SM3withSM2", "Kona");
        verifier.initVerify(certificate);
        verifier.update(DATA);
        boolean verified = verifier.verify(sign);
        Assertions.assertTrue(verified);
    }

    private static PrivateKey privateKey(String pkcs8PEM)
            throws NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchProviderException {
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                Base64.getMimeDecoder().decode(removeBELines(pkcs8PEM)));
        KeyFactory keyFactory = KeyFactory.getInstance(
                "EC", "Kona");
        return keyFactory.generatePrivate(privateKeySpec);
    }

    private static String removeBELines(String pkcs8PEM) {
        return pkcs8PEM.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "");
    }

    private static Certificate certificate(String certPEM)
            throws CertificateException, NoSuchProviderException {
        CertificateFactory certFactory = CertificateFactory.getInstance(
                "X.509", "Kona");
        return certFactory.generateCertificate(
                new ByteArrayInputStream(certPEM.getBytes(StandardCharsets.UTF_8)));
    }

    // This test uses the provider's utilities for fast development.
    @Test
    public void testSignatureWithCustomAPI() throws Exception {
        PrivateKey privateKey = PKIXUtils.getPrivateKey("EC", KEY);
        Signature signer = Signature.getInstance("SM3withSM2", "Kona");
        signer.initSign(privateKey);
        signer.update(DATA);
        byte[] sign = signer.sign();

        Certificate certificate = PKIXUtils.getCertificate(CERT);
        Signature verifier = Signature.getInstance("SM3withSM2", "Kona");
        verifier.initVerify(certificate);
        verifier.update(DATA);
        Assertions.assertTrue(verifier.verify(sign));
    }
}
