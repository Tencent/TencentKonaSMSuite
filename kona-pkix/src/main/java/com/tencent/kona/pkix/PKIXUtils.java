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

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.crypto.spec.RFC5915EncodedKeySpec;
import com.tencent.kona.sun.security.util.DerInputStream;
import com.tencent.kona.sun.security.util.KnownOIDs;
import com.tencent.kona.sun.security.util.NamedCurve;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Set;

/**
 * The utilities for this provider.
 */
public class PKIXUtils {

    private static final String PRIVATE_KEY_BEGIN = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_KEY_END = "-----END PRIVATE KEY-----";

    private static final String EC_PARAMS_BEGIN = "-----BEGIN EC PARAMETERS-----";
    private static final String EC_PARAMS_END = "-----END EC PARAMETERS-----";

    private static final String RFC5915_KEY_BEGIN = "-----BEGIN EC PRIVATE KEY-----";
    private static final String RFC5915_KEY_END = "-----END EC PRIVATE KEY-----";

    private static final String PUBLIC_KEY_BEGIN = "-----BEGIN PUBLIC KEY-----";
    private static final String PUBLIC_KEY_END = "-----END PUBLIC KEY-----";

    public static boolean isSM3withSM2(String algName) {
        return "SM3withSM2".equalsIgnoreCase(algName)
                || "sm2sig_sm3".equalsIgnoreCase(algName);
    }

    // Parse named curve from an EC parameter PEM.
    // This PEM contains an object identifier representing a named curve,
    // e.g. 06 08 2A 81 1C CF 55 01 82 2D -- 1.2.156.10197.1.301, SM2 curve
    public static String getNamedCurveId(String ecParams)
            throws IOException {
        String keyPem = ecParams.replace(EC_PARAMS_BEGIN, "")
                .replace(EC_PARAMS_END, "");
        DerInputStream derIn = new DerInputStream(
                Base64.getMimeDecoder().decode(keyPem));
        return derIn.getOID().toString();
    }

    // Create a PrivateKey from a PKCS#8-encoded PEM.
    public static PrivateKey getPrivateKey(String keyAlgo, String pkcs8Key)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String keyPem = pkcs8Key.replace(PRIVATE_KEY_BEGIN, "")
                .replace(PRIVATE_KEY_END, "");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                Base64.getMimeDecoder().decode(keyPem));
        KeyFactory keyFactory = CryptoInsts.getKeyFactory(keyAlgo);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    // Create an ECPrivateKey from a RFC5915-encoded PEM.
    public static PrivateKey getRFC5915PrivateKey(String rfc5915Key)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String keyPem = rfc5915Key.replace(RFC5915_KEY_BEGIN, "")
                .replace(RFC5915_KEY_END, "");
        RFC5915EncodedKeySpec privateKeySpec = new RFC5915EncodedKeySpec(
                Base64.getMimeDecoder().decode(keyPem));
        KeyFactory keyFactory = CryptoInsts.getKeyFactory("EC");
        return keyFactory.generatePrivate(privateKeySpec);
    }

    // Create a PublicKey from an X.509-encoded PEM.
    public static PublicKey getPublicKey(String keyAlgo, String x509Key)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String keyPem = x509Key.replace(PUBLIC_KEY_BEGIN, "")
                .replace(PUBLIC_KEY_END, "");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                Base64.getMimeDecoder().decode(keyPem));
        KeyFactory keyFactory = CryptoInsts.getKeyFactory(keyAlgo);
        return keyFactory.generatePublic(publicKeySpec);
    }

    public static PublicKey getPublicKey(Certificate cert)
            throws InvalidKeyException {
        // If the certificate is of type X509Certificate,
        // we should check whether it has a Key Usage
        // extension marked as critical.
        if (cert instanceof X509Certificate) {
            // Check whether the cert has a key usage extension
            // marked as a critical extension.
            // The OID for KeyUsage extension is 2.5.29.15.
            X509Certificate c = (X509Certificate)cert;
            Set<String> criticalExtSet = c.getCriticalExtensionOIDs();

            if (criticalExtSet != null && !criticalExtSet.isEmpty()
                && criticalExtSet.contains("2.5.29.15")) {
                boolean[] keyUsageInfo = c.getKeyUsage();
                // keyUsageInfo[0] is for digitalSignature.
                if ((keyUsageInfo != null) && !keyUsageInfo[0]) {
                    throw new InvalidKeyException("Wrong key usage");
                }
            }
        }
        return cert.getPublicKey();
    }

    // Create a PublicKey from an X.509 PEM.
    public static PublicKey getPublicKey(String certPEM)
            throws InvalidKeyException, CertificateException {
        return getPublicKey(getCertificate(certPEM));
    }

    public static X509Certificate getCertificate(String certPEM)
            throws CertificateException {
        return (X509Certificate) PKIXInsts.getCertificateFactory("X.509")
                .generateCertificate(new ByteArrayInputStream(
                        certPEM.getBytes(StandardCharsets.UTF_8)));
    }

    // An SM certificate must use curveSM2 as ECC curve
    // and SM2withSM3 as signature scheme.
    public static boolean isSMCert(X509Certificate cert) {
        if (!(cert.getPublicKey() instanceof ECPublicKey)) {
            return false;
        }

        NamedCurve curve = (NamedCurve) ((ECPublicKey) cert.getPublicKey()).getParams();
        return KnownOIDs.curveSM2.value().equals(curve.getObjectId())
                && KnownOIDs.SM3withSM2.value().equals(cert.getSigAlgOID());
    }

    // CA has basic constraints extension.
    public static boolean isCA(X509Certificate certificate) {
        return certificate.getBasicConstraints() != -1;
    }

    // If the key usage is critical, it must contain digitalSignature.
    public static boolean isSignCert(X509Certificate certificate) {
        if (certificate == null) {
            return false;
        }

        boolean[] keyUsage = certificate.getKeyUsage();
        return keyUsage == null || keyUsage[0];
    }

    // If the key usage is critical, it must contain one or more of
    // keyEncipherment, dataEncipherment and keyAgreement.
    public static boolean isEncCert(X509Certificate certificate) {
        if (certificate == null) {
            return false;
        }

        boolean[] keyUsage = certificate.getKeyUsage();
        return keyUsage == null || keyUsage[2] || keyUsage[3] || keyUsage[4];
    }
}
