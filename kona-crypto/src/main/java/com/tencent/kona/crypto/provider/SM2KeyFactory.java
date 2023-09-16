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

package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.spec.SM2PrivateKeySpec;
import com.tencent.kona.crypto.spec.SM2PublicKeySpec;
import com.tencent.kona.crypto.CryptoUtils;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class SM2KeyFactory extends KeyFactorySpi {

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec)
            throws InvalidKeySpecException {
        if (keySpec instanceof SM2PublicKeySpec) {
            SM2PublicKeySpec spec = (SM2PublicKeySpec) keySpec;
            byte[] key = CryptoUtils.pubKey(spec.getW());
            if (key == null || key.length == 0) {
                throw new InvalidKeySpecException(
                        "Invalid SM2PublicKeySpec, empty Key");
            }

            return new SM2PublicKey(key);
        }

        throw new InvalidKeySpecException(
                "Only accept SM2PublicKeySpec: " + keySpec);
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
            throws InvalidKeySpecException {
        if (keySpec instanceof SM2PrivateKeySpec) {
            SM2PrivateKeySpec spec = (SM2PrivateKeySpec) keySpec;
            byte[] key = spec.getS().toByteArray();
            if (key == null || key.length == 0) {
                throw new InvalidKeySpecException("No private key");
            }

            return new SM2PrivateKey(key);
        }

        throw new InvalidKeySpecException(
                "Only accept SM2PrivateKeySpec: " + keySpec);
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {
        byte[] encoded = key.getEncoded();
        if (key instanceof ECPrivateKey) {
            return keySpec.cast(new SM2PrivateKeySpec(encoded));
        }

        if (key instanceof ECPublicKey) {
            return keySpec.cast(new SM2PublicKeySpec(encoded));
        }

        throw new InvalidKeySpecException(
                "The key must be ECPrivateKey or ECPublicKey");
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof ECPrivateKey) {
            return new SM2PrivateKey(((ECPrivateKey) key).getS());
        }

        if (key instanceof ECPublicKey) {
            return new SM2PublicKey(((ECPublicKey) key).getW());
        }

        throw new InvalidKeyException(
                "The key must be ECPrivateKey or ECPublicKey: " + key);
    }
}
