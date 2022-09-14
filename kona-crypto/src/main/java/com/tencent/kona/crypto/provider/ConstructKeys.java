package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.CryptoInsts;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

final class ConstructKeys {

    static Key constructKey(byte[] encoding, String keyAlgorithm, int keyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        switch (keyType) {
            case Cipher.SECRET_KEY:
                return constructSecretKey(encoding, keyAlgorithm);
            case Cipher.PRIVATE_KEY:
                return constructPrivateKey(encoding, keyAlgorithm);
            case Cipher.PUBLIC_KEY:
                return constructPublicKey(encoding, keyAlgorithm);
        }

        return null;
    }

    private static PublicKey constructPublicKey(
            byte[] encodedKey, String encodedKeyAlgo)
            throws InvalidKeyException, NoSuchAlgorithmException {

        try {
            KeyFactory keyFactory =
                    CryptoInsts.getKeyFactory(encodedKeyAlgo);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException nsae) {
            throw new NoSuchAlgorithmException(
                    "Unknown algorithm: " + encodedKeyAlgo, nsae);
        } catch (InvalidKeySpecException ikse) {
            throw new InvalidKeyException("Cannot construct public key", ikse);
        }
    }

    private static PrivateKey constructPrivateKey(
            byte[] encodedKey, String encodedKeyAlgo)
            throws InvalidKeyException, NoSuchAlgorithmException {
        try {
            KeyFactory keyFactory =
                    CryptoInsts.getKeyFactory(encodedKeyAlgo);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException nsae) {
            throw new NoSuchAlgorithmException(
                    "Unknown algorithm: " + encodedKeyAlgo, nsae);
        } catch (InvalidKeySpecException ikse) {
            throw new InvalidKeyException(
                    "Cannot construct private key", ikse);
        }
    }

    private static SecretKey constructSecretKey(
            byte[] encodedKey, String encodedKeyAlgorithm) {
        return (new SecretKeySpec(encodedKey, encodedKeyAlgorithm));
    }
}
