package com.tencent.kona.crypto.provider;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import static com.tencent.kona.crypto.util.Constants.SM4_KEY_SIZE;

public class SM3HMacKeyGenerator extends KeyGeneratorSpi {

    private int keySize = 32; // The key size in bytes.
    private SecureRandom random;

    @Override
    protected void engineInit(SecureRandom random) {
        this.random = random;
        this.keySize = 32;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("No parameter is needed");
    }

    @Override
    protected void engineInit(int keySize, SecureRandom random) {
        if (keySize < (SM4_KEY_SIZE << 3)) {
            throw new InvalidParameterException("Key size must be 128-bits at least");
        }

        this.keySize = (keySize + 7) >> 3;
        this.random = random;
    }

    @Override
    protected SecretKey engineGenerateKey() {
        if (random == null) {
            random = new SecureRandom();
        }

        byte[] key = new byte[keySize];
        random.nextBytes(key);
        return new SecretKeySpec(key, "SM3HMac");
    }
}
