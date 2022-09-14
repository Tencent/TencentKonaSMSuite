package com.tencent.kona.crypto.provider;

import org.bouncycastle.jcajce.provider.asymmetric.ec.GMCipherSpi;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class SM2Cipher extends GMCipherSpi {

    public SM2Cipher() {
        super(new SM2Engine());
    }

    @Override
    public void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (!mode.equalsIgnoreCase("none")) {
            throw new NoSuchAlgorithmException("Mode must be none");
        }
    }

    @Override
    public void engineSetPadding(String paddingName)
            throws NoSuchPaddingException {
        if (!paddingName.equalsIgnoreCase("NoPadding")) {
            throw new NoSuchPaddingException("Padding must be NoPadding");
        }
    }

    @Override
    public void engineInit(int opmode, Key key, SecureRandom random)
            throws InvalidKeyException {
        super.engineInit(opmode, key, random);
    }

    @Override
    public void engineInit(int opmode, Key key,
            AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        super.engineInit(opmode, key, params, random);
    }

    @Override
    public void engineInit(int opmode, Key key,
            AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        super.engineInit(opmode, key, params, random);
    }

    @Override
    public byte[] engineUpdate(byte[] in, int inOfs, int inLen) {
        throw new UnsupportedOperationException(
                "update() is not supported yet, please use doFinal() instead.");
    }

    @Override
    public int engineUpdate(byte[] in, int inOfs, int inLen, byte[] out,
            int outOfs) {
        throw new UnsupportedOperationException(
                "update() is not supported yet, please use doFinal() instead.");
    }

    @Override
    public byte[] engineDoFinal(byte[] in, int inOfs, int inLen)
            throws IllegalBlockSizeException, BadPaddingException {
        // BC cannot process empty input
        if (inLen == 0) {
            return new byte[0];
        }
        return super.engineDoFinal(in, inOfs, inLen);
    }

    @Override
    public int engineDoFinal(byte[] in, int inOfs, int inLen, byte[] out,
            int outOfs) throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException {
        return super.engineDoFinal(in, inOfs, inLen, out, outOfs);
    }

    @Override
    public byte[] engineWrap(Key key) throws InvalidKeyException,
            IllegalBlockSizeException {
        byte[] encoded = key.getEncoded();
        if (encoded == null || encoded.length == 0) {
            throw new InvalidKeyException("No encoded key");
        }

        try {
            return engineDoFinal(encoded, 0, encoded.length);
        } catch (BadPaddingException e) {
            throw new InvalidKeyException("Wrap key failed", e);
        }
    }

    @Override
    public Key engineUnwrap(byte[] wrappedKey, String algorithm,
            int type) throws InvalidKeyException, NoSuchAlgorithmException {
        if (wrappedKey == null || wrappedKey.length == 0) {
            throw new InvalidKeyException("No wrapped key");
        }

        byte[] encoded;
        try {
            encoded = engineDoFinal(wrappedKey, 0, wrappedKey.length);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new InvalidKeyException("Unwrap key failed", e);
        }

        return ConstructKeys.constructKey(encoded, algorithm, type);
    }

    @Override
    public AlgorithmParameters engineGetParameters() {
        return super.engineGetParameters();
    }

    @Override
    public byte[] engineGetIV() {
        return super.engineGetIV();
    }

    @Override
    public int engineGetBlockSize() {
        return super.engineGetBlockSize();
    }

    @Override
    public int engineGetOutputSize(int inputLen) {
        return super.engineGetOutputSize(inputLen);
    }

    @Override
    public int engineGetKeySize(Key key) {
        return super.engineGetKeySize(key);
    }
}
