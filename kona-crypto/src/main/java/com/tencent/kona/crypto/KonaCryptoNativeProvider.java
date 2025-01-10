/*
 * Copyright (C) 2024, 2025, THL A29 Limited, a Tencent company. All rights reserved.
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

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

/**
 * The Kona Crypto Provider based on OpenSSL.
 */
public class KonaCryptoNativeProvider extends Provider {

    static final String NAME = "KonaCrypto-Native";

    private static final double VERSION_NUM = 1.0D;

    private static final String INFO = "Kona crypto provider based on OpenSSL "
            + "(implements SM2, SM3 and SM4 algorithms)";

    private static volatile KonaCryptoNativeProvider instance = null;

    public KonaCryptoNativeProvider() {
        super(NAME, VERSION_NUM, INFO);

        AccessController.doPrivileged(
                (PrivilegedAction<Void>) () -> {
                    putEntries(this);

                    return null;
                });
    }

    private static void putEntries(Provider provider) {
        putSMEntries(provider);
        KonaCryptoProvider.putSMPBES2Entries(provider);
        KonaCryptoProvider.putECEntries(provider);
        SunRsaSignEntries.putEntries(provider);
    }

    private static void putSMEntries(Provider provider) {
        provider.put("Cipher.SM4 SupportedPaddings", "NOPADDING|PKCS7PADDING");
        provider.put("Cipher.SM4 SupportedModes", "CBC|CTR|ECB|GCM");
        provider.put("Cipher.SM4",
                "com.tencent.kona.crypto.provider.nativeImpl.SM4Cipher");;
        provider.put("AlgorithmParameters.SM4",
                "com.tencent.kona.crypto.provider.SM4Parameters");
        provider.put("AlgorithmParameterGenerator.SM4",
                "com.tencent.kona.crypto.provider.SM4ParameterGenerator");
        provider.put("KeyGenerator.SM4",
                "com.tencent.kona.crypto.provider.SM4KeyGenerator");

        provider.put("Alg.Alias.MessageDigest.OID.1.2.156.10197.1.401", "SM3");
        provider.put("MessageDigest.SM3",
                "com.tencent.kona.crypto.provider.nativeImpl.SM3MessageDigest");
        provider.put("Mac.HmacSM3",
                "com.tencent.kona.crypto.provider.nativeImpl.SM3HMac");
        provider.put("Alg.Alias.Mac.SM3HMac", "HmacSM3");
        provider.put("KeyGenerator.HmacSM3",
                "com.tencent.kona.crypto.provider.SM3HMacKeyGenerator");
        provider.put("Alg.Alias.KeyGenerator.SM3HMac", "HmacSM3");

        provider.put("Alg.Alias.Cipher.OID.1.2.156.10197.1.301", "SM2");
        provider.put("Alg.Alias.Signature.OID.1.2.156.10197.1.501", "SM2");
        provider.put("KeyPairGenerator.SM2",
                "com.tencent.kona.crypto.provider.nativeImpl.SM2KeyPairGenerator");
        provider.put("Cipher.SM2", "com.tencent.kona.crypto.provider.nativeImpl.SM2Cipher");
        provider.put("Signature.SM2", "com.tencent.kona.crypto.provider.nativeImpl.SM2Signature");
        provider.put("Alg.Alias.Signature.SM3withSM2", "SM2");
        provider.put("KeyAgreement.SM2", "com.tencent.kona.crypto.provider.nativeImpl.SM2KeyAgreement");
        provider.put("KeyFactory.SM2", "com.tencent.kona.crypto.provider.SM2KeyFactory");
    }

    public static KonaCryptoNativeProvider instance() {
        if (instance == null) {
            instance = new KonaCryptoNativeProvider();
        }
        return instance;
    }
}
