package com.tencent.kona.crypto.provider;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import static com.tencent.kona.crypto.util.Constants.SM4_KEY_SIZE;

public final class SM4KeyGenerator extends KeyGeneratorSpi {

    // The key size in bytes
    private int keySize = SM4_KEY_SIZE;

    private SecureRandom random;

    @Override
    protected void engineInit(SecureRandom random) {
        this.random = random;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params,
                              SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("No need parameters");
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        if (keysize != SM4_KEY_SIZE << 3) {
            throw new InvalidParameterException("The key size must be 128-bits");
        }

        this.keySize = SM4_KEY_SIZE;
        this.engineInit(random);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        if (random == null) {
            random = new SecureRandom();
        }

        byte[] keyBytes = new byte[keySize];
        random.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "SM4");
    }
}
