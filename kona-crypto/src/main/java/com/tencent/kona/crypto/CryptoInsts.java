package com.tencent.kona.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class CryptoInsts {

    static final String PROV_NAME = CryptoUtils.privilegedGetProperty(
            "com.tencent.kona.crypto.provider.name", KonaCryptoProvider.NAME);

    private static final Set<String> ALGO_PARAMS_ALGOS
            = new HashSet<>(Arrays.asList("EC", "SM4", "RSASSA-PSS", "PBES2"));

    public static AlgorithmParameters getAlgorithmParameters(String algorithm)
            throws NoSuchAlgorithmException {
        AlgorithmParameters algoParams  = null;
        if (ALGO_PARAMS_ALGOS.contains(algorithm)) {
            try {
                algoParams = AlgorithmParameters.getInstance(algorithm, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            algoParams = AlgorithmParameters.getInstance(algorithm);
        }
        return algoParams;
    }

    private static final Set<String> ALGO_PARAM_GEN_ALGOS
            = new HashSet<>(Collections.singletonList("SM4"));

    public static AlgorithmParameterGenerator getAlgorithmParameterGenerator(
            String algorithm) throws NoSuchAlgorithmException {
        AlgorithmParameterGenerator algoParamGen  = null;
        if (ALGO_PARAM_GEN_ALGOS.contains(algorithm)) {
            try {
                algoParamGen = AlgorithmParameterGenerator.getInstance(algorithm, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            algoParamGen = AlgorithmParameterGenerator.getInstance(algorithm);
        }
        return algoParamGen;
    }

    private static final Set<String> KEY_FACTORY_ALGOS
            = new HashSet<>(Arrays.asList("EC", "SM2", "RSA", "RSASSA-PSS"));

    public static KeyFactory getKeyFactory(String algorithm)
            throws NoSuchAlgorithmException {
        KeyFactory keyFactory  = null;
        if (KEY_FACTORY_ALGOS.contains(algorithm)) {
            try {
                keyFactory = KeyFactory.getInstance(algorithm, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            keyFactory = KeyFactory.getInstance(algorithm);
        }
        return keyFactory;
    }

    private static final Set<String> KEY_GEN_ALGOS
            = new HashSet<>(Arrays.asList("SM3HMac", "SM4"));

    public static KeyGenerator getKeyGenerator(String algorithm)
            throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator  = null;
        if (KEY_GEN_ALGOS.contains(algorithm)) {
            try {
                keyGenerator = KeyGenerator.getInstance(algorithm, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            keyGenerator = KeyGenerator.getInstance(algorithm);
        }
        return keyGenerator;
    }

    private static final Set<String> KEY_PAIR_GEN_ALGOS
            = new HashSet<>(Arrays.asList("SM2", "RSA", "RSASSA-PSS"));

    public static KeyPairGenerator getKeyPairGenerator(String algorithm)
            throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator  = null;
        if (KEY_PAIR_GEN_ALGOS.contains(algorithm)) {
            try {
                keyPairGenerator = KeyPairGenerator.getInstance(algorithm, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        }
        return keyPairGenerator;
    }

    private static final Set<String> CIPHER_ALGOS
            = new HashSet<>(Arrays.asList("SM2", "SM4"));

    public static Cipher getCipher(String algorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher  = null;
        if (CIPHER_ALGOS.contains(algorithm)) {
            try {
                cipher = Cipher.getInstance(algorithm, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            cipher = Cipher.getInstance(algorithm);
        }
        return cipher;
    }

    private static final Set<String> MESSAGE_DIGEST_ALGOS
            = new HashSet<>(Collections.singletonList("SM3"));

    public static MessageDigest getMessageDigest(String algorithm)
            throws NoSuchAlgorithmException {
        MessageDigest messageDigest  = null;
        if (MESSAGE_DIGEST_ALGOS.contains(algorithm)) {
            try {
                messageDigest = MessageDigest.getInstance(algorithm, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            messageDigest = MessageDigest.getInstance(algorithm);
        }

        return messageDigest;
    }

    private static final Set<String> MAC_ALGOS
            = new HashSet<>(Collections.singletonList("SM3HMac"));

    public static Mac getMac(String algorithm) throws NoSuchAlgorithmException {
        Mac mac  = null;
        if (MAC_ALGOS.contains(algorithm)) {
            try {
                mac = Mac.getInstance(algorithm, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
             mac = Mac.getInstance(algorithm);
        }
        return mac;
    }

    private static final Set<String> SIGNATURE_ALGOS
            = new HashSet<>(Arrays.asList(
                    "SM2", "SM3withSM2",
                    "NONEwithECDSA", "SHA1withECDSA",
                    "SHA224withECDSA", "SHA256withECDSA",
                    "SHA384withECDSA", "SHA512withECDSA",
                    "SHA1withRSA", "SHA224withRSA",
                    "SHA256withRSA", "SHA384withRSA",
                    "SHA512withRSA", "SHA512/224withRSA",
                    "SHA512/256withRSA", "SHA3-224withRSA",
                    "SHA3-256withRSA", "SHA3-384withRSA",
                    "SHA3-512withRSA"));

    public static Signature getSignature(String algorithm)
            throws NoSuchAlgorithmException {
        Signature signature  = null;
        if (SIGNATURE_ALGOS.contains(algorithm)) {
            try {
                signature = Signature.getInstance(algorithm, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            signature = Signature.getInstance(algorithm);
        }
        return signature;
    }

    private static final Set<String> KEY_AGREEMENT_ALGOS
            = new HashSet<>(Arrays.asList("SM2", "ECDH"));

    public static KeyAgreement getKeyAgreement(String algorithm)
            throws NoSuchAlgorithmException {
        KeyAgreement keyAgreement  = null;
        if (KEY_AGREEMENT_ALGOS.contains(algorithm)) {
            try {
                keyAgreement = KeyAgreement.getInstance(algorithm, PROV_NAME);
            } catch (NoSuchProviderException e) {
                throw new IllegalStateException("No provider: " + PROV_NAME, e);
            }
        } else {
            keyAgreement = KeyAgreement.getInstance(algorithm);
        }
        return keyAgreement;
    }
}
