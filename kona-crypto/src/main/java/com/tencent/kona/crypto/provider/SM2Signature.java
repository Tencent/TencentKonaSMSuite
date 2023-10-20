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

import com.tencent.kona.crypto.spec.SM2ParameterSpec;
import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;
import com.tencent.kona.sun.security.ec.point.MutablePoint;
import com.tencent.kona.sun.security.jca.JCAUtil;
import com.tencent.kona.sun.security.util.ArrayUtil;
import com.tencent.kona.sun.security.util.DerInputStream;
import com.tencent.kona.sun.security.util.DerOutputStream;
import com.tencent.kona.sun.security.util.DerValue;
import com.tencent.kona.sun.security.util.ECUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.Objects;

import static com.tencent.kona.crypto.CryptoUtils.bigIntToBytes32;
import static com.tencent.kona.crypto.CryptoUtils.toByteArrayLE;
import static com.tencent.kona.crypto.spec.SM2ParameterSpec.CURVE;
import static com.tencent.kona.crypto.spec.SM2ParameterSpec.GENERATOR;
import static com.tencent.kona.crypto.spec.SM2ParameterSpec.ORDER;
import static com.tencent.kona.crypto.util.Constants.defaultId;
import static com.tencent.kona.sun.security.ec.SM2Operations.isInfinitePoint;
import static com.tencent.kona.sun.security.ec.SM2Operations.SM2OPS;
import static com.tencent.kona.sun.security.ec.SM2Operations.toECPoint;
import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;

public class SM2Signature extends SignatureSpi {

    private static final String PARAM_ID = "id";
    private static final String PARAM_PUBLIC_KEY = "publicKey";

    private SM2PrivateKey privateKey;
    private SM2PublicKey publicKey;
    private byte[] id;

    private SecureRandom random;

    private byte[] z;

    private final MessageDigest sm3MD = new SM3MessageDigest();

    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
            throws InvalidKeyException {
        this.privateKey = null;
        z = null;

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
        this.random = random != null ? random : JCAUtil.getSecureRandom();

        if (publicKey == null) {
            publicKey = new SM2PublicKey(toECPoint(
                    SM2OPS.multiply(GENERATOR,
                            toByteArrayLE((ecPrivateKey.getS())))));
        }

        resetDigest();
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
        z = null;

        if (!(publicKey instanceof ECPublicKey)) {
            throw new InvalidKeyException("Only ECPublicKey accepted!");
        }

        this.publicKey = new SM2PublicKey((ECPublicKey) publicKey);

        resetDigest();
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
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
        Objects.requireNonNull(param);
        Objects.requireNonNull(value);

        if (isParamId(param)) {
            id = ((byte[]) value).clone();
        } else if (isParamPublicKey(param)) {
            SM2PublicKey key = new SM2PublicKey((ECPublicKey) value);
            byte[] encodedKey = key.getEncoded();

            if (encodedKey.length == 0) {
                throw new InvalidParameterException(
                        "Invalid public key of parameter");
            }

            if (publicKey != null) {
                if (!Arrays.equals(publicKey.getEncoded(), encodedKey)) {
                    throw new InvalidParameterException(
                            "public key of parameter is not match");
                }
            }
        } else {
            throw new InvalidParameterException("unsupported parameter: " + param);
        }
    }

    @Override
    protected Object engineGetParameter(String param)
            throws InvalidParameterException {
        if (isParamId(param)) {
            return id == null ? defaultId() : id.clone();
        } else if (isParamPublicKey(param)) {
            return publicKey;
        } else {
            throw new InvalidParameterException(
                    "Only support id and publicKey: " + param);
        }
    }

    private static boolean isParamId(String paramName) {
        return PARAM_ID.equalsIgnoreCase(paramName);
    }

    private static boolean isParamPublicKey(String paramName) {
        return PARAM_PUBLIC_KEY.equalsIgnoreCase(paramName);
    }

    private void resetDigest() {
        sm3MD.reset();
        if (z == null) {
            z = z();
        }
        sm3MD.update(z);
    }

    private byte[] getDigestValue() {
        byte[] digest = sm3MD.digest();
        resetDigest();
        return digest;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        sm3MD.update(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len)
            throws SignatureException {
        sm3MD.update(b, off, len);
    }

    @Override
    protected void engineUpdate(ByteBuffer byteBuffer) {
        int len = byteBuffer.remaining();
        if (len <= 0) {
            return;
        }

        sm3MD.update(byteBuffer);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (privateKey == null) {
            throw new SignatureException("Private Key not initialized");
        }

        BigInteger d = privateKey.getS();

        byte[] eHash = getDigestValue();

        // A2
        BigInteger e = new BigInteger(1, eHash);

        BigInteger r;
        BigInteger s;
        do {
            BigInteger k;
            do {
                // A3
                byte[] kArr = nextK();

                // A4
                MutablePoint p = SM2OPS.multiply(GENERATOR, kArr);

                // Little-Endian bytes to Big-Endian BigInteger
                ArrayUtil.reverse(kArr);
                k = new BigInteger(1, kArr);

                // A5
                r = e.add(p.asAffine().toECPoint().getAffineX()).mod(ORDER);
            } while (r.equals(ZERO) || r.add(k).equals(ORDER));

            // A6
            s = d.add(ONE).modInverse(ORDER)
                    .multiply(k.subtract(r.multiply(d)).mod(ORDER))
                    .mod(ORDER);
        } while (s.equals(ZERO));

        // A7
        return encodeSignature(r, s);
    }

    private byte[] nextK() {
        return SM2OPS.generatePrivateScalar(random);
    }

    private byte[] encodeSignature(BigInteger r, BigInteger s)
            throws SignatureException {
        try {
            DerOutputStream out = new DerOutputStream();
            out.putInteger(r);
            out.putInteger(s);
            DerValue result = new DerValue(
                    DerValue.tag_Sequence, out.toByteArray());
            return result.toByteArray();
        } catch (Exception e) {
            throw new SignatureException("Could not encode signature", e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (publicKey == null) {
            throw new SignatureException("Public Key not initialized");
        }

        ECPoint publicPoint = publicKey.getW();

        // Partial public key validation
        try {
            ECUtil.validatePublicKey(publicPoint, SM2ParameterSpec.instance());
        } catch (InvalidKeyException e) {
            return false;
        }

        BigInteger[] values = decodeSignature(sigBytes);
        BigInteger r = values[0];
        BigInteger s = values[1];

        // B1
        if (r.compareTo(ONE) < 0 || r.compareTo(ORDER) >= 0) {
            return false;
        }

        // B2
        if (s.compareTo(ONE) < 0 || s.compareTo(ORDER) >= 0) {
            return false;
        }

        // B3
        byte[] eHash = getDigestValue();

        // B4
        BigInteger e = new BigInteger(1, eHash);

        // B5
        BigInteger t = r.add(s).mod(ORDER);
        if (t.equals(ZERO)) {
            return false;
        }

        // B6: p = S'G + tPA
        MutablePoint p = SM2OPS.multiply(GENERATOR, toByteArrayLE(s));
        MutablePoint p2 = SM2OPS.multiply(publicPoint, toByteArrayLE(t));
        SM2OPS.setSum(p, p2.asAffine());
        if (isInfinitePoint(p)) {
            return false;
        }
        ECPoint point = toECPoint(p);

        // B7
        BigInteger expectedR = e.add(point.getAffineX()).mod(ORDER);
        return expectedR.equals(r);
    }

    private BigInteger[] decodeSignature(byte[] signature)
            throws SignatureException {
        try {
            // Enforce strict DER checking for signatures
            DerInputStream in = new DerInputStream(signature, 0, signature.length, false);
            DerValue[] values = in.getSequence(2);

            // check number of components in the read sequence
            // and trailing data
            if ((values.length != 2) || (in.available() != 0)) {
                throw new IOException("Invalid encoding for signature");
            }

            BigInteger r = values[0].getPositiveBigInteger();
            BigInteger s = values[1].getPositiveBigInteger();

            return new BigInteger[] { r, s };
        } catch (Exception e) {
            throw new SignatureException("Could not decode signature", e);
        }
    }

    private static final byte[] A = bigIntToBytes32(CURVE.getA());
    private static final byte[] B = bigIntToBytes32(CURVE.getB());
    private static final byte[] GEN_X = bigIntToBytes32(GENERATOR.getAffineX());
    private static final byte[] GEN_Y = bigIntToBytes32(GENERATOR.getAffineY());

    private byte[] z() {
        MessageDigest md = new SM3MessageDigest();

        byte[] userId = id == null ? defaultId() : id;
        int userIdLen = userId.length << 3;
        md.update((byte)(userIdLen >>> 8));
        md.update((byte)userIdLen);
        md.update(userId);

        md.update(A);
        md.update(B);

        md.update(GEN_X);
        md.update(GEN_Y);

        ECPoint pubPoint = publicKey.getW();
        md.update(bigIntToBytes32(pubPoint.getAffineX()));
        md.update(bigIntToBytes32(pubPoint.getAffineY()));

        return md.digest();
    }
}
