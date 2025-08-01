/*
 * Copyright (C) 2022, 2025, Tencent. All rights reserved.
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

import com.tencent.kona.crypto.util.Constants;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
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
import java.util.Arrays;

import static com.tencent.kona.crypto.util.Constants.*;

public abstract class SM4Cipher extends CipherSpi {

    private final CipherCore core;

    public SM4Cipher() {
        core = new CipherCore(getInnerCipher());
    }

    abstract protected SymmetricCipher getInnerCipher();

    public static class Native extends SM4Cipher {

        @Override
        protected SymmetricCipher getInnerCipher() {
            return new SM4Crypt();
        }
    }

    public static class NativeOneShot extends SM4Cipher {

        @Override
        protected SymmetricCipher getInnerCipher() {
            return new SM4OneShotCrypt();
        }
    }

    @Override
    protected void engineSetMode(String mode)
            throws NoSuchAlgorithmException {
        core.setMode(mode);
    }

    @Override
    protected void engineSetPadding(String paddingScheme)
            throws NoSuchPaddingException {
        core.setPadding(paddingScheme);
    }

    @Override
    protected int engineGetBlockSize() {
        return SM4_BLOCK_SIZE;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return core.getOutputSize(inputLen);
    }

    @Override
    protected byte[] engineGetIV() {
        return core.getIV();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return core.getParameters("SM4");
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
            throws InvalidKeyException {
        core.init(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key,
                              AlgorithmParameterSpec params,
                              SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        core.init(opmode, key, params, random);
    }

    @Override
    protected void engineInit(int opmode, Key key,
                              AlgorithmParameters params,
                              SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        core.init(opmode, key, params, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        return core.update(input, inputOffset, inputLen);
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                               byte[] output, int outputOffset)
            throws ShortBufferException {
        return core.update(input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        try {
            return core.doFinal(input, inputOffset, inputLen);
        } catch (IllegalStateException e) {
            if (e.getCause() instanceof BadPaddingException) {
                throw (BadPaddingException) e.getCause();
            } else {
                throw e;
            }
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                                byte[] output, int outputOffset)
            throws IllegalBlockSizeException, ShortBufferException,
            BadPaddingException {
        try {
            return core.doFinal(input, inputOffset, inputLen, output,
                    outputOffset);
        } catch (IllegalStateException e) {
            if (e.getCause() instanceof BadPaddingException) {
                throw (BadPaddingException) e.getCause();
            } else {
                throw e;
            }
        }
    }

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        byte[] encoded = key.getEncoded();
        Arrays.fill(encoded, (byte)0);
        if (encoded.length != Constants.SM4_KEY_SIZE) {
            throw new InvalidKeyException("Invalid SM4 key length: " +
                    encoded.length + " bytes");
        }
        return Math.multiplyExact(encoded.length, 8);
    }

    @Override
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException,
            InvalidKeyException {
        return core.wrap(key);
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey,
                               String wrappedKeyAlgorithm,
                               int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        return core.unwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        core.updateAAD(src, offset, len);
    }
}
