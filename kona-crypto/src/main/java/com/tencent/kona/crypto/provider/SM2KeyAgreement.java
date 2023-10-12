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

import com.tencent.kona.crypto.spec.SM2KeyAgreementParamSpec;
import com.tencent.kona.sun.security.ec.point.MutablePoint;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECPoint;

import static com.tencent.kona.crypto.spec.SM2ParameterSpec.COFACTOR;
import static com.tencent.kona.crypto.spec.SM2ParameterSpec.CURVE;
import static com.tencent.kona.crypto.spec.SM2ParameterSpec.GENERATOR;
import static com.tencent.kona.crypto.spec.SM2ParameterSpec.ORDER;
import static com.tencent.kona.crypto.util.Constants.defaultId;
import static com.tencent.kona.crypto.util.Constants.SM3_DIGEST_LEN;
import static com.tencent.kona.crypto.util.Constants.INFINITY;
import static com.tencent.kona.crypto.CryptoUtils.bigIntToBytes32;
import static com.tencent.kona.crypto.CryptoUtils.intToBytes4;
import static com.tencent.kona.crypto.CryptoUtils.toByteArrayLE;
import static com.tencent.kona.sun.security.ec.SM2Operations.SM2OPS;
import static com.tencent.kona.sun.security.ec.SM2Operations.toECPoint;

/**
 * SM2 key agreement in compliance with GB/T 32918.3-2016.
 */
public class SM2KeyAgreement extends KeyAgreementSpi {

    private SM2KeyAgreementParamSpec paramSpec;
    private ECPrivateKey ephemeralPrivateKey;
    private ECPublicKey peerEphemeralPublicKey;

    private final SM3Engine sm3 = new SM3Engine();

    @Override
    protected void engineInit(Key key, SecureRandom random) {
        throw new UnsupportedOperationException(
                "Use init(Key, AlgorithmParameterSpec, SecureRandom) instead");
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params,
            SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(key instanceof ECPrivateKey)) {
            throw new InvalidKeyException("Only accept ECPrivateKey");
        }

        if (!(params instanceof SM2KeyAgreementParamSpec)) {
            throw new InvalidAlgorithmParameterException(
                    "Only accept SM2KeyAgreementParamSpec");
        }

        paramSpec = (SM2KeyAgreementParamSpec) params;
        ephemeralPrivateKey = (ECPrivateKey) key;
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {
        if (ephemeralPrivateKey == null || paramSpec == null) {
            throw new IllegalStateException("Not initialized");
        }

        if (peerEphemeralPublicKey != null) {
            throw new IllegalStateException("Phase already executed");
        }

        if (!lastPhase) {
            throw new IllegalStateException(
                    "Only two party agreement supported, lastPhase must be true");
        }

        if (!(key instanceof ECPublicKey)) {
            throw new InvalidKeyException("Only accept ECPublicKey");
        }

        peerEphemeralPublicKey = (ECPublicKey) key;

        return null;
    }

    private static final BigInteger TWO_POW_W = BigInteger.ONE.shiftLeft(w());
    private static final BigInteger TWO_POW_W_SUB_ONE
            = TWO_POW_W.subtract(BigInteger.ONE);

    // w = ceil(ceil(log2(n) / 2) - 1
    private static int w() {
        return (int) Math.ceil((double) ORDER.subtract(
                BigInteger.ONE).bitLength() / 2) - 1;
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        // RA = rA * G = (x1, y1)
        BigInteger rA = ephemeralPrivateKey.getS();
        MutablePoint rAMutablePoint = SM2OPS.multiply(
                GENERATOR, toByteArrayLE(rA));
        BigInteger x1 = rAMutablePoint.asAffine().getX().asBigInteger();

        // x1Bar = 2 ^ w + (x1 & (2 ^ w - 1))
        BigInteger x1Bar = TWO_POW_W.add(x1.and(TWO_POW_W_SUB_ONE));

        // tA = (dA + x1Bar * rA) mod n
        BigInteger dA = paramSpec.privateKey.getS();
        BigInteger tA = dA.add(x1Bar.multiply(rA)).mod(ORDER);

        // RB = (x2, y2)
        ECPoint rBPubPoint = peerEphemeralPublicKey.getW();
        BigInteger x2 = rBPubPoint.getAffineX();

        // x2Bar = 2 ^ w + (x2 & (2 ^ w - 1))
        BigInteger x2Bar = TWO_POW_W.add(x2.and(TWO_POW_W_SUB_ONE));

        // U = (h * tA) * (PB + x2Bar * RB)
        ECPoint pBPubPoint = paramSpec.peerPublicKey.getW();
        MutablePoint interimMutablePoint = SM2OPS.multiply(
                rBPubPoint, toByteArrayLE(x2Bar));
        SM2OPS.setSum(interimMutablePoint, SM2OPS.toAffinePoint(pBPubPoint));
        ECPoint uPoint = toECPoint(SM2OPS.multiply(
                interimMutablePoint.asAffine(),
                toByteArrayLE(COFACTOR.multiply(tA))));

        if (uPoint.equals(INFINITY)) {
            throw new IllegalStateException("Generate secret failed");
        }

        byte[] vX = bigIntToBytes32(uPoint.getAffineX());
        byte[] vY = bigIntToBytes32(uPoint.getAffineY());

        byte[] zA = z(paramSpec.id, paramSpec.publicKey.getW());
        byte[] zB = z(paramSpec.peerId, paramSpec.peerPublicKey.getW());

        byte[] combined = combine(vX, vY, zA, zB);
        return kdf(combined);
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException {
        if (offset + paramSpec.sharedKeyLength > sharedSecret.length) {
            throw new ShortBufferException("Need " + paramSpec.sharedKeyLength
                    + " bytes, only " + (sharedSecret.length - offset)
                    + " available");
        }

        byte[] secret = engineGenerateSecret();
        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
        return secret.length;
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException {
        if (algorithm == null) {
            throw new NoSuchAlgorithmException("Algorithm must not be null");
        }

        return new SecretKeySpec(engineGenerateSecret(), algorithm);
    }

    private static final byte[] A = bigIntToBytes32(CURVE.getA());
    private static final byte[] B = bigIntToBytes32(CURVE.getB());
    private static final byte[] GEN_X = bigIntToBytes32(GENERATOR.getAffineX());
    private static final byte[] GEN_Y = bigIntToBytes32(GENERATOR.getAffineY());

    private byte[] z(byte[] origId, ECPoint pubPoint) {
        byte[] id = origId == null ? defaultId() : origId;
        int idLen = id.length << 3;
        sm3.update((byte)(idLen >>> 8));
        sm3.update((byte)idLen);
        sm3.update(id);

        sm3.update(A);
        sm3.update(B);

        sm3.update(GEN_X);
        sm3.update(GEN_Y);

        sm3.update(bigIntToBytes32(pubPoint.getAffineX()));
        sm3.update(bigIntToBytes32(pubPoint.getAffineY()));

        return sm3.doFinal();
    }

    private byte[] kdf(byte[] input) {
        byte[] derivedKey = new byte[paramSpec.sharedKeyLength];
        byte[] digest = new byte[SM3_DIGEST_LEN];

        int remainder = paramSpec.sharedKeyLength % SM3_DIGEST_LEN;
        int count = paramSpec.sharedKeyLength / SM3_DIGEST_LEN + (remainder == 0 ? 0 : 1);
        for (int i = 1; i <= count; i++) {
            sm3.update(input);
            sm3.update(intToBytes4(i));
            sm3.doFinal(digest);

            int length = i == count && remainder != 0 ? remainder : SM3_DIGEST_LEN;
            System.arraycopy(digest, 0, derivedKey, (i - 1) * SM3_DIGEST_LEN, length);
        }

        return derivedKey;
    }

    // vX || vY || ZA || ZB, isInitiator = true
    // vX || vY || ZB || ZA, isInitiator = false
    private byte[] combine(byte[] vX, byte[] vY, byte[] zA, byte[] zB) {
        byte[] result = new byte[vX.length + vY.length + zA.length + zB.length];

        System.arraycopy(vX, 0, result, 0, vX.length);
        System.arraycopy(vY, 0, result, vX.length, vY.length);

        if (paramSpec.isInitiator) {
            System.arraycopy(zA, 0, result, vX.length + vY.length, zA.length);
            System.arraycopy(zB, 0, result, vX.length + vY.length + zA.length, zB.length);
        } else {
            System.arraycopy(zB, 0, result, vX.length + vY.length, zB.length);
            System.arraycopy(zA, 0, result, vX.length + vY.length + zB.length, zA.length);
        }

        return result;
    }
}
