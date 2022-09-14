package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.spec.SM2ParameterSpec;
import com.tencent.kona.crypto.util.Constants;
import com.tencent.kona.sun.security.ec.point.Point;
import com.tencent.kona.sun.security.util.ArrayUtil;

import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

import static com.tencent.kona.sun.security.ec.ECOperations.SM2OPS;
import static com.tencent.kona.sun.security.ec.ECOperations.toECPoint;

public class SM2KeyPairGenerator extends KeyPairGeneratorSpi {

    private SecureRandom random;

    @Override
    public void initialize(int keySize, SecureRandom random) {
        if (keySize != Constants.SM2_PRIKEY_LEN << 3) {
            throw new IllegalArgumentException(
                    "keySize must be 256-bit: " + keySize);
        }

        this.random = random;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) {
        if (!(params instanceof ECParameterSpec)) {
            throw new IllegalArgumentException(
                    "params must be ECParameterSpec: " + params);
        }

        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair() {
        if (random == null) {
            random = new SecureRandom();
        }

        byte[] privArr = SM2OPS.generatePrivateScalar(random);
        Point point = SM2OPS.multiply(
                SM2ParameterSpec.instance().getGenerator(), privArr);
        ECPoint w = toECPoint(point);
        PublicKey publicKey = new SM2PublicKey(w);

        // Convert little-endian to big-endian
        ArrayUtil.reverse(privArr);
        PrivateKey privateKey = new SM2PrivateKey(privArr);
        Arrays.fill(privArr, (byte)0);

        return new KeyPair(publicKey, privateKey);
    }
}
