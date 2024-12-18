/*
 * Copyright (C) 2022, 2024, THL A29 Limited, a Tencent company. All rights reserved.
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

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class CryptoInsts {

    public static final Provider PROV = CryptoUtils.useNativeCrypto()
            ? KonaCryptoNativeProvider.instance()
            : KonaCryptoProvider.instance();

    private static final Set<String> ALGO_PARAMS_ALGOS
            = new HashSet<>(Arrays.asList("EC", "SM4", "PBES2"));

    public static AlgorithmParameters getAlgorithmParameters(String algorithm)
            throws NoSuchAlgorithmException {
        AlgorithmParameters algoParams  = null;
        if (ALGO_PARAMS_ALGOS.contains(algorithm)) {
            algoParams = AlgorithmParameters.getInstance(algorithm, PROV);
        } else {
            algoParams = AlgorithmParameters.getInstance(algorithm);
        }
        return algoParams;
    }

    private static final Set<String> KEY_FACTORY_ALGOS
            = new HashSet<>(Arrays.asList("EC", "SM2"));

    public static KeyFactory getKeyFactory(String algorithm)
            throws NoSuchAlgorithmException {
        KeyFactory keyFactory  = null;
        if (KEY_FACTORY_ALGOS.contains(algorithm)) {
            keyFactory = KeyFactory.getInstance(algorithm, PROV);
        } else {
            keyFactory = KeyFactory.getInstance(algorithm);
        }
        return keyFactory;
    }

    private static final Set<String> KEY_GEN_ALGOS
            = new HashSet<>(Arrays.asList("SM4", "HmacSM3", "SM3HMac"));

    public static KeyGenerator getKeyGenerator(String algorithm)
            throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator  = null;
        if (KEY_GEN_ALGOS.contains(algorithm)) {
            keyGenerator = KeyGenerator.getInstance(algorithm, PROV);
        } else {
            keyGenerator = KeyGenerator.getInstance(algorithm);
        }
        return keyGenerator;
    }

    private static final Set<String> KEY_PAIR_GEN_ALGOS
            = new HashSet<>(Arrays.asList("SM2"));

    public static KeyPairGenerator getKeyPairGenerator(String algorithm, Provider prov)
            throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator  = null;
        if (KEY_PAIR_GEN_ALGOS.contains(algorithm)) {
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm, prov);
        } else {
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        }
        return keyPairGenerator;
    }

    public static KeyPairGenerator getKeyPairGenerator(String algorithm)
            throws NoSuchAlgorithmException {
        return getKeyPairGenerator(algorithm, PROV);
    }

    private static final Set<String> CIPHER_ALGOS
            = new HashSet<>(Arrays.asList("SM2", "SM4"));

    public static Cipher getCipher(String algorithm, Provider prov)
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher  = null;
        if (CIPHER_ALGOS.contains(algorithm)) {
            cipher = Cipher.getInstance(algorithm, prov);
        } else {
            cipher = Cipher.getInstance(algorithm);
        }
        return cipher;
    }

    public static Cipher getCipher(String algorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        return getCipher(algorithm, PROV);
    }

    private static final Set<String> MESSAGE_DIGEST_ALGOS
            = new HashSet<>(Collections.singletonList("SM3"));

    public static MessageDigest getMessageDigest(String algorithm, Provider prov)
            throws NoSuchAlgorithmException {
        MessageDigest messageDigest  = null;
        if (MESSAGE_DIGEST_ALGOS.contains(algorithm)) {
            messageDigest = MessageDigest.getInstance(algorithm, prov);
        } else {
            messageDigest = MessageDigest.getInstance(algorithm);
        }

        return messageDigest;
    }

    public static MessageDigest getMessageDigest(String algorithm)
            throws NoSuchAlgorithmException {
        return getMessageDigest(algorithm,
                // use pure Java-based SM3 for TLCP/TLS protocol
                KonaCryptoProvider.instance());
    }

    private static final Set<String> MAC_ALGOS
            = new HashSet<>(Arrays.asList("HmacSM3", "SM3HMac"));

    public static Mac getMac(String algorithm, Provider prov)
            throws NoSuchAlgorithmException {
        Mac mac  = null;
        if (MAC_ALGOS.contains(algorithm)) {
            mac = Mac.getInstance(algorithm, prov);
        } else {
            mac = Mac.getInstance(algorithm);
        }
        return mac;
    }

    public static Mac getMac(String algorithm) throws NoSuchAlgorithmException {
        return getMac(algorithm,
                // use pure Java-based SM3HMac for TLCP/TLS protocol
                KonaCryptoProvider.instance());
    }

    private static final Set<String> SIGNATURE_ALGOS
            = new HashSet<>(Arrays.asList(
                    "SM2", "SM3withSM2",
                    "NONEwithECDSA", "SHA1withECDSA",
                    "SHA224withECDSA", "SHA256withECDSA",
                    "SHA384withECDSA", "SHA512withECDSA"));

    public static Signature getSignature(String algorithm, Provider prov)
            throws NoSuchAlgorithmException {
        Signature signature  = null;
        if (SIGNATURE_ALGOS.contains(algorithm)) {
            signature = Signature.getInstance(algorithm, prov);
        } else {
            signature = Signature.getInstance(algorithm);
        }
        return signature;
    }

    public static Signature getSignature(String algorithm)
            throws NoSuchAlgorithmException {
        return getSignature(algorithm, PROV);
    }

    private static final Set<String> KEY_AGREEMENT_ALGOS
            = new HashSet<>(Arrays.asList("SM2", "ECDH"));

    public static KeyAgreement getKeyAgreement(String algorithm, Provider prov)
            throws NoSuchAlgorithmException {
        KeyAgreement keyAgreement  = null;
        if (KEY_AGREEMENT_ALGOS.contains(algorithm)) {
            keyAgreement = KeyAgreement.getInstance(algorithm, prov);
        } else {
            keyAgreement = KeyAgreement.getInstance(algorithm);
        }
        return keyAgreement;
    }

    public static KeyAgreement getKeyAgreement(String algorithm)
            throws NoSuchAlgorithmException {
        return getKeyAgreement(algorithm, PROV);
    }
}
