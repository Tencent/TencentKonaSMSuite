/*
 * Copyright (C) 2022, 2024, Tencent. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. Tencent designates
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
