package com.tencent.kona.pkix;

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.sun.security.util.KnownOIDs;
import com.tencent.kona.sun.security.util.NamedCurve;

import java.io.ByteArrayInputStream;
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
import java.util.Base64;
import java.util.Set;

/**
 * The utilities for this provider.
 */
public class PKIXUtils {

    public static final String PKCS8_KEY_BEGIN = "-----BEGIN PRIVATE KEY-----";
    public static final String PKCS8_KEY_END = "-----END PRIVATE KEY-----";

    public static boolean isSM3withSM2(String algName) {
        return "SM3withSM2".equalsIgnoreCase(algName)
                || "sm2sig_sm3".equalsIgnoreCase(algName);
    }

    // Create a PrivateKey from a PKCS#8-encoded PEM.
    public static PrivateKey getPrivateKey(String keyAlgo, String pkcs8Key)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String keyPem = pkcs8Key.replace(PKCS8_KEY_BEGIN, "")
                .replace(PKCS8_KEY_END, "");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                Base64.getMimeDecoder().decode(keyPem));
        KeyFactory keyFactory = CryptoInsts.getKeyFactory(keyAlgo);
        return keyFactory.generatePrivate(privateKeySpec);
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
