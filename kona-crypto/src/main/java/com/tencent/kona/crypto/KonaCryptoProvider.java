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
                "com.tencent.kona.crypto.provider.SM4Cipher$General");
        provider.put("Cipher.SM4 SupportedModes", "CBC|CTR|ECB");
        provider.put("Cipher.SM4 SupportedPaddings", "NOPADDING|PKCS7PADDING");
        provider.put("Cipher.SM4/GCM/NoPadding",
                "com.tencent.kona.crypto.provider.GaloisCounterMode$SM4");
        provider.put("AlgorithmParameters.SM4",
                "com.tencent.kona.crypto.provider.SM4Parameters");
        provider.put("AlgorithmParameterGenerator.SM4",
                "com.tencent.kona.crypto.provider.SM4ParameterGenerator");
        provider.put("KeyGenerator.SM4",
                "com.tencent.kona.crypto.provider.SM4KeyGenerator");

        provider.put("Alg.Alias.MessageDigest.OID.1.2.156.10197.1.401", "SM3");
        provider.put("MessageDigest.SM3",
                "com.tencent.kona.crypto.provider.SM3MessageDigest");
        provider.put("Mac.HmacSM3",
                "com.tencent.kona.crypto.provider.SM3HMac");
        provider.put("Alg.Alias.Mac.SM3HMac", "HmacSM3");
        provider.put("KeyGenerator.HmacSM3",
                "com.tencent.kona.crypto.provider.SM3HMacKeyGenerator");
        provider.put("Alg.Alias.KeyGenerator.SM3HMac", "HmacSM3");

        provider.put("Alg.Alias.Cipher.OID.1.2.156.10197.1.301", "SM2");
        provider.put("Alg.Alias.Signature.OID.1.2.156.10197.1.501", "SM3withSM2");
        provider.put("KeyPairGenerator.SM2",
                "com.tencent.kona.crypto.provider.SM2KeyPairGenerator");
        provider.put("KeyFactory.SM2", "com.tencent.kona.crypto.provider.SM2KeyFactory");
        provider.put("Cipher.SM2", "com.tencent.kona.crypto.provider.SM2Cipher");
        provider.put("Signature.SM2", "com.tencent.kona.crypto.provider.SM2Signature");
        provider.put("Signature.SM3withSM2", "com.tencent.kona.crypto.provider.SM2Signature");
        provider.put("KeyAgreement.SM2", "com.tencent.kona.crypto.provider.SM2KeyAgreement");

        // PBES2 on SM
        provider.put("AlgorithmParameters.PBES2",
                "com.tencent.kona.crypto.provider.PBES2Parameters$General");
        provider.put("AlgorithmParameters.PBEWithHmacSM3AndSM4",
                "com.tencent.kona.crypto.provider.PBES2Parameters$HmacSM3AndSM4");
        provider.put("Alg.Alias.AlgorithmParameters.PBEWithHmacSM3AndSM4_128",
                "PBEWithHmacSM3AndSM4");
        provider.put("Mac.HmacPBESM3",
                "com.tencent.kona.crypto.provider.HmacPKCS12PBE_SM3");
        provider.put("SecretKeyFactory.PBEWithHmacSM3AndSM4",
                "com.tencent.kona.crypto.provider.PBEKeyFactory$PBEWithHmacSM3AndSM4");
        provider.put("Alg.Alias.SecretKeyFactory.PBEWithHmacSM3AndSM4_128",
                "PBEWithHmacSM3AndSM4");
        provider.put("Cipher.PBEWithHmacSM3AndSM4",
                "com.tencent.kona.crypto.provider.PBES2Core$HmacSM3AndSM4");
        provider.put("Alg.Alias.Cipher.PBEWithHmacSM3AndSM4_128",
                "PBEWithHmacSM3AndSM4");

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
