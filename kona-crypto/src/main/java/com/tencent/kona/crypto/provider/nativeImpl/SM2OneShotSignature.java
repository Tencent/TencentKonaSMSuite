/*
 * Copyright (C) 2022, 2025, THL A29 Limited, a Tencent company. All rights reserved.
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

package com.tencent.kona.crypto.provider.nativeImpl;

import com.tencent.kona.crypto.provider.SM2PrivateKey;
import com.tencent.kona.crypto.provider.SM2PublicKey;
import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;

import javax.crypto.BadPaddingException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import static com.tencent.kona.crypto.spec.SM2ParameterSpec.ORDER;
import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;

public final class SM2OneShotSignature extends SignatureSpi {

    // The default ID 1234567812345678
    private static final byte[] DEFAULT_ID = new byte[] {
            49, 50, 51, 52, 53, 54, 55, 56,
            49, 50, 51, 52, 53, 54, 55, 56};

    private SM2PrivateKey privateKey;
    private SM2PublicKey publicKey;
    private byte[] id;

    private final ByteArrayWriter buffer = new ByteArrayWriter();

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
            throws InvalidKeyException {
        this.privateKey = null;
        buffer.reset();

        if (!(privateKey instanceof ECPrivateKey)) {
            throw new InvalidKeyException("Only ECPrivateKey accepted!");
        }

        ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;

        BigInteger s = ecPrivateKey.getS();
        if (s.compareTo(ZERO) <= 0 || s.compareTo(ORDER.subtract(ONE)) >= 0) {
            throw new InvalidKeyException("The private key must be " +
                    "within the range [1, n - 2]");
        }

        this.privateKey = new SM2PrivateKey(ecPrivateKey);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey)
            throws InvalidKeyException {
        engineInitSign(privateKey, null);
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException {
        this.privateKey = null;
        this.publicKey = null;
        buffer.reset();

        if (!(publicKey instanceof ECPublicKey)) {
            throw new InvalidKeyException("Only ECPublicKey accepted!");
        }

        this.publicKey = new SM2PublicKey((ECPublicKey) publicKey);
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        privateKey = null;
        publicKey = null;
        id = null;

        if (!(params instanceof SM2SignatureParameterSpec)) {
            throw new InvalidAlgorithmParameterException(
                    "Only accept SM2SignatureParameterSpec");
        }

        SM2SignatureParameterSpec paramSpec = (SM2SignatureParameterSpec) params;
        publicKey = new SM2PublicKey(paramSpec.getPublicKey());
        id = paramSpec.getId();
    }

    @Override
    protected void engineSetParameter(String param, Object value)
            throws InvalidParameterException {
        throw new UnsupportedOperationException(
                "Use setParameter(AlgorithmParameterSpec params) instead");
    }

    @Override
    protected Object engineGetParameter(String param)
            throws InvalidParameterException {
        throw new UnsupportedOperationException(
                "getParameter(String param) not supported");
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        byte[] buf = new byte[] {b};
        buffer.write(buf, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len)
            throws SignatureException {
        buffer.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (privateKey == null) {
            throw new SignatureException("Private key not initialized");
        }

        if (id == null) {
            id = DEFAULT_ID.clone();
        }

        try (NativeSM2Signature sm2 = new NativeSM2Signature(
                privateKey.getEncoded(),
                publicKey != null ? publicKey.getEncoded() : null,
                id, true)) {
            return sm2.sign(buffer.toByteArray());
        } catch (BadPaddingException e) {
            throw new SignatureException(e);
        } finally {
            buffer.reset();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (publicKey == null) {
            throw new SignatureException("Public key not initialized");
        }

        if (id == null) {
            id = DEFAULT_ID.clone();
        }

        try (NativeSM2Signature sm2 = new NativeSM2Signature(
                null, publicKey.getEncoded(), id, false)) {
            return sm2.verify(buffer.toByteArray(), sigBytes);
        } catch (BadPaddingException e) {
            throw new SignatureException(e);
        } finally {
            buffer.reset();
        }
    }
}
