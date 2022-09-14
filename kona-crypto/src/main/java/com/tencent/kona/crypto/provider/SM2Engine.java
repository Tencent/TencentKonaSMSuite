package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.util.SM2Ciphertext;
import com.tencent.kona.crypto.CryptoUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;

public final class SM2Engine extends org.bouncycastle.crypto.engines.SM2Engine {

    private boolean forEncryption;

    @Override
    public void init(boolean forEncryption, CipherParameters param) {
        super.init(forEncryption, param);
        this.forEncryption = forEncryption;
    }

    @Override
    public byte[] processBlock(byte[] in, int inOff, int inLen)
            throws InvalidCipherTextException {
        if (forEncryption) {
            return encrypt(in, inOff, inLen);
        } else {
            return decrypt(in, inOff, inLen);
        }
    }

    private byte[] encrypt(byte[] in, int inOff, int inLen)
            throws InvalidCipherTextException {
        // Raw C1|C2|C3
        byte[] rawCiphertextBC = super.processBlock(in, inOff, inLen);

        try {
            return SM2Ciphertext.builder()
                    .format(SM2Ciphertext.Format.RAW_C1C2C3)
                    .encodedCiphertext(rawCiphertextBC)
                    .build()
                    .derC1C3C2();
        } catch (IOException e) {
            throw new InvalidCipherTextException(
                    "Convert ciphertext from raw C1|C2|C3 to der C1|C3|C2 failed", e);
        }
    }

    byte[] decrypt(byte[] in, int inOff, int inLen)
            throws InvalidCipherTextException {
        // DER C1|C3|C2
        byte[] ciphertext = CryptoUtils.copy(in, inOff, inLen);

        try {
            byte[] ciphertextBC = SM2Ciphertext.builder()
                    .format(SM2Ciphertext.Format.DER_C1C3C2)
                    .encodedCiphertext(ciphertext)
                    .build()
                    .rawC1C2C3();
            return super.processBlock(ciphertextBC, 0, ciphertextBC.length);
        } catch (IOException e) {
            throw new InvalidCipherTextException(
                    "Convert ciphertext from der C1|C3|C2 to raw C1|C2|C3 failed", e);
        }
    }
}
