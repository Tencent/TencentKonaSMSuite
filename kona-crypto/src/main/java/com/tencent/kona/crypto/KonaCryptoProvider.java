package com.tencent.kona.crypto;

import com.tencent.kona.sun.security.rsa.SunRsaSignEntries;
import com.tencent.kona.sun.security.util.CurveDB;
import com.tencent.kona.sun.security.util.NamedCurve;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.Collection;
import java.util.regex.Pattern;

/**
 * The Kona Crypto Provider.
 */
public class KonaCryptoProvider extends Provider {

    static final String NAME = "KonaCrypto";

    private static final double VERSION_NUM = 1.0D;

    private static final String INFO = "Kona crypto provider "
            + "(implements SM2, SM3 and SM4 algorithms)";

    public KonaCryptoProvider() {
        super(NAME, VERSION_NUM, INFO);

        AccessController.doPrivileged(
                (PrivilegedAction<Void>) () -> {
                    putEntries(this);

                    return null;
                });
    }

    private static void putEntries(Provider provider) {
        SunRsaSignEntries.putEntries(provider);

        provider.put("Cipher.SM4",
                "org.bouncycastle.jcajce.provider.symmetric.SM4$ECB");
        provider.put("Cipher.SM4 SupportedModes", "CBC|CTR|ECB|GCM");
        provider.put("Cipher.SM4 SupportedPaddings", "NOPADDING|PKCS7PADDING");
        provider.put("AlgorithmParameters.SM4",
                "com.tencent.kona.crypto.provider.SM4Parameters");
        provider.put("AlgorithmParameterGenerator.SM4",
                "org.bouncycastle.jcajce.provider.symmetric.SM4$AlgParamGen");
        provider.put("KeyGenerator.SM4",
                "com.tencent.kona.crypto.provider.SM4KeyGenerator");

        provider.put("Alg.Alias.MessageDigest.OID.1.2.156.10197.1.401", "SM3");
        provider.put("MessageDigest.SM3",
                "com.tencent.kona.crypto.provider.SM3MessageDigest");
        provider.put("Mac.SM3HMac",
                "com.tencent.kona.crypto.provider.SM3HMac");
        provider.put("Mac.HmacSM3",
                "com.tencent.kona.crypto.provider.SM3HMac");
        provider.put("KeyGenerator.SM3HMac",
                "com.tencent.kona.crypto.provider.SM3HMacKeyGenerator");

        provider.put("Alg.Alias.Cipher.OID.1.2.156.10197.1.301", "SM2");
        provider.put("Alg.Alias.Signature.OID.1.2.156.10197.1.501", "SM3withSM2");
        provider.put("KeyPairGenerator.SM2",
                "com.tencent.kona.crypto.provider.SM2KeyPairGenerator");
        provider.put("KeyFactory.SM2", "com.tencent.kona.crypto.provider.SM2KeyFactory");
        provider.put("Cipher.SM2", "com.tencent.kona.crypto.provider.SM2Cipher");
        provider.put("Signature.SM2", "com.tencent.kona.crypto.provider.SM2Signature");
        provider.put("Signature.SM3withSM2", "com.tencent.kona.crypto.provider.SM2Signature");
        provider.put("KeyAgreement.SM2", "com.tencent.kona.crypto.provider.SM2KeyAgreement");

        /*
         * Algorithm Parameter engine
         */
        provider.put("Alg.Alias.AlgorithmParameters.1.2.840.10045.2.1", "EC");
        provider.put("AlgorithmParameters.EC",
                "com.tencent.kona.sun.security.util.ECParameters");
        provider.put("Alg.Alias.AlgorithmParameters.EllipticCurve", "EC");

        // "AlgorithmParameters.EC SupportedCurves" prop used by unit test
        boolean firstCurve = true;
        StringBuilder names = new StringBuilder();
        Pattern nameSplitPattern = Pattern.compile(CurveDB.SPLIT_PATTERN);

        Collection<? extends NamedCurve> supportedCurves =
                CurveDB.getSupportedCurves();
        for (NamedCurve namedCurve : supportedCurves) {
            if (!firstCurve) {
                names.append("|");
            } else {
                firstCurve = false;
            }

            names.append("[");

            String[] commonNames = nameSplitPattern.split(namedCurve.getName());
            for (String commonName : commonNames) {
                names.append(commonName.trim());
                names.append(",");
            }

            names.append(namedCurve.getObjectId());
            names.append("]");
        }

        provider.put("AlgorithmParameters.EC SupportedCurves", names.toString());

        provider.put("KeyFactory.EC",
                "com.tencent.kona.sun.security.ec.ECKeyFactory");
        provider.put("Alg.Alias.KeyFactory.EllipticCurve", "EC");

        provider.put("AlgorithmParameters.EC KeySize", "256");

        /*
         * Signature engines
         */
        provider.put("Signature.NONEwithECDSA",
                "com.tencent.kona.sun.security.ec.ECDSASignature$Raw");
        provider.put("Signature.SHA1withECDSA",
                "com.tencent.kona.sun.security.ec.ECDSASignature$SHA1");
        provider.put("Alg.Alias.Signature.OID.1.2.840.10045.4.1", "SHA1withECDSA");
        provider.put("Alg.Alias.Signature.1.2.840.10045.4.1", "SHA1withECDSA");

        provider.put("Signature.SHA224withECDSA",
                "com.tencent.kona.sun.security.ec.ECDSASignature$SHA224");
        provider.put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.1", "SHA224withECDSA");
        provider.put("Alg.Alias.Signature.1.2.840.10045.4.3.1", "SHA224withECDSA");

        provider.put("Signature.SHA256withECDSA",
                "com.tencent.kona.sun.security.ec.ECDSASignature$SHA256");
        provider.put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.2", "SHA256withECDSA");
        provider.put("Alg.Alias.Signature.1.2.840.10045.4.3.2", "SHA256withECDSA");

        provider.put("Signature.SHA384withECDSA",
                "com.tencent.kona.sun.security.ec.ECDSASignature$SHA384");
        provider.put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.3", "SHA384withECDSA");
        provider.put("Alg.Alias.Signature.1.2.840.10045.4.3.3", "SHA384withECDSA");

        provider.put("Signature.SHA512withECDSA",
                "com.tencent.kona.sun.security.ec.ECDSASignature$SHA512");
        provider.put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.4", "SHA512withECDSA");
        provider.put("Alg.Alias.Signature.1.2.840.10045.4.3.4", "SHA512withECDSA");

        String ecKeyClasses = "java.security.interfaces.ECPublicKey" +
                "|java.security.interfaces.ECPrivateKey";
        provider.put("Signature.NONEwithECDSA SupportedKeyClasses", ecKeyClasses);
        provider.put("Signature.SHA1withECDSA SupportedKeyClasses", ecKeyClasses);
        provider.put("Signature.SHA224withECDSA SupportedKeyClasses", ecKeyClasses);
        provider.put("Signature.SHA256withECDSA SupportedKeyClasses", ecKeyClasses);
        provider.put("Signature.SHA384withECDSA SupportedKeyClasses", ecKeyClasses);
        provider.put("Signature.SHA512withECDSA SupportedKeyClasses", ecKeyClasses);

        provider.put("Signature.SHA1withECDSA KeySize", "256");

        /*
         *  Key Pair Generator engine
         */
        provider.put("KeyPairGenerator.EC", "com.tencent.kona.sun.security.ec.ECKeyPairGenerator");
        provider.put("Alg.Alias.KeyPairGenerator.EllipticCurve", "EC");

        provider.put("KeyPairGenerator.EC KeySize", "256");
        provider.put("KeyPairGenerator.SM KeySize", "256");

        /*
         * Key Agreement engine
         */
        provider.put("KeyAgreement.ECDH", "com.tencent.kona.sun.security.ec.ECDHKeyAgreement");
        provider.put("KeyAgreement.ECDH SupportedKeyClasses", ecKeyClasses);
    }
}
