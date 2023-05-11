package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.util.Constants;

import java.security.InvalidKeyException;

public class SM4Crypt extends SymmetricCipher {

    private SM4Engine engine;

    @Override
    int getBlockSize() {
        return Constants.SM4_BLOCK_SIZE;
    }

    @Override
    void init(boolean decrypting, String algorithm, byte[] key)
            throws InvalidKeyException {
        if (!algorithm.equalsIgnoreCase("SM4")) {
            throw new InvalidKeyException("The algorithm must be SM4");
        }

        engine = new SM4Engine(key, !decrypting);
    }

    @Override
    void encryptBlock(byte[] plain, int plainOffset,
                      byte[] cipher, int cipherOffset) {
        engine.processBlock(plain, plainOffset, cipher, cipherOffset);
    }

    @Override
    void decryptBlock(byte[] cipher, int cipherOffset,
                      byte[] plain, int plainOffset) {
        engine.processBlock(cipher, cipherOffset, plain, plainOffset);
    }
}
