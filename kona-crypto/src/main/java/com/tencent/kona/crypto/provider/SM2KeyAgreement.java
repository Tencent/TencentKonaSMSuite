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
import java.security.MessageDigest;
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
import static com.tencent.kona.crypto.CryptoUtils.intToBytes32;
import static com.tencent.kona.crypto.CryptoUtils.intToBytes4;
import static com.tencent.kona.crypto.CryptoUtils.toByteArrayLE;
import static com.tencent.kona.sun.security.ec.ECOperations.INFINITY;
import static com.tencent.kona.sun.security.ec.ECOperations.SM2OPS;
import static com.tencent.kona.sun.security.ec.ECOperations.toECPoint;

/**
 * SM2 key agreement in compliance with GB/T 32918.3-2016.
 */
public class SM2KeyAgreement extends KeyAgreementSpi {

    private SM2KeyAgreementParamSpec paramSpec;
    private ECPrivateKey ephemeralPrivateKey;
    private ECPublicKey peerEphemeralPublicKey;

    private final MessageDigest sm3MD = new SM3MessageDigest();

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

        byte[] vX = intToBytes32(uPoint.getAffineX());
        byte[] vY = intToBytes32(uPoint.getAffineY());

        byte[] zA = z(paramSpec.id, paramSpec.publicKey.getW());
        byte[] zB = z(paramSpec.peerId, paramSpec.peerPublicKey.getW());

        return kdf(vX, vY, zA, zB);
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

    private static final byte[] A = intToBytes32(CURVE.getA());
    private static final byte[] B = intToBytes32(CURVE.getB());
    private static final byte[] GEN_X = intToBytes32(GENERATOR.getAffineX());
    private static final byte[] GEN_Y = intToBytes32(GENERATOR.getAffineY());

    private byte[] z(byte[] origId, ECPoint pubPoint) {
        byte[] id = origId == null ? defaultId() : origId;
        int idLen = id.length << 3;
        sm3MD.update((byte)(idLen >>> 8));
        sm3MD.update((byte)idLen);
        sm3MD.update(id);

        sm3MD.update(A);
        sm3MD.update(B);

        sm3MD.update(GEN_X);
        sm3MD.update(GEN_Y);

        sm3MD.update(intToBytes32(pubPoint.getAffineX()));
        sm3MD.update(intToBytes32(pubPoint.getAffineY()));

        return sm3MD.digest();
    }

    private byte[] kdf(byte[] vX, byte[] vY, byte[] zA, byte[] zB) {
        byte[] combined = combine(vX, vY, zA, zB);
        byte[] derivedKey = new byte[paramSpec.sharedKeyLength];

        int reminder = paramSpec.sharedKeyLength % SM3_DIGEST_LEN;
        int count = paramSpec.sharedKeyLength / SM3_DIGEST_LEN + (reminder == 0 ? 0 : 1);
        for (int i = 1; i <= count; i++) {
            int length = i == count && reminder != 0 ? reminder : SM3_DIGEST_LEN;

            sm3MD.update(combined);
            sm3MD.update(intToBytes4(i));
            byte[] digest = sm3MD.digest();
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
