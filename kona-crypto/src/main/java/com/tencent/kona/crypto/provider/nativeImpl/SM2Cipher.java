/*
 * Copyright (C) 2022, 2024, Tencent. All rights reserved.
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

import com.tencent.kona.crypto.provider.SM2PrivateKey;
import com.tencent.kona.crypto.provider.SM2PublicKey;
import com.tencent.kona.crypto.util.Sweeper;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import static com.tencent.kona.crypto.spec.SM2ParameterSpec.ORDER;
import static com.tencent.kona.crypto.util.Constants.SM2_CURVE_FIELD_SIZE;
import static com.tencent.kona.crypto.util.Constants.SM3_DIGEST_LEN;
import static java.math.BigInteger.ZERO;

public final class SM2Cipher extends CipherSpi {

    private static final Sweeper SWEEPER = Sweeper.instance();

    private static final byte[] B0 = new byte[0];

    private NativeSM2Cipher sm2;
    private final ByteArrayWriter buffer = new ByteArrayWriter();

    private boolean encrypted = true;

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
        buffer.reset();

        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
            encrypted = true;

            if (key instanceof ECPublicKey) {
                SM2PublicKey publicKey = new SM2PublicKey((ECPublicKey) key);
                sm2 = new NativeSM2Cipher(publicKey.getEncoded());
            } else {
                throw new InvalidKeyException(
                        "Only accept ECPublicKey for encryption");
            }
        } else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) {
            encrypted = false;

            if (key instanceof ECPrivateKey) {
                SM2PrivateKey privateKey = new SM2PrivateKey((ECPrivateKey) key);

                BigInteger s = privateKey.getS();
                if (s.compareTo(ZERO) <= 0 || s.compareTo(ORDER) >= 0) {
                    throw new InvalidKeyException("The private key must be " +
                            "within the range [1, n - 1]");
                }

                sm2 = new NativeSM2Cipher(privateKey.getEncoded());
            } else {
                throw new InvalidKeyException(
                        "Only accept ECPrivateKey for decryption");
            }
        }

        SWEEPER.register(this, new SweepNativeRef(sm2));
    }

    @Override
    public void engineInit(int opmode, Key key,
            AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, random);
    }

    @Override
    public void engineInit(int opmode, Key key,
            AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException(
                    "Not need AlgorithmParameters");
        }

        engineInit(opmode, key, random);
    }

    @Override
    public byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        buffer.write(input, inputOffset, inputLen);
        return B0;
    }

    @Override
    public int engineUpdate(byte[] input, int inputOffset, int inputLen,
                            byte[] output, int outputOffset) {
        buffer.write(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    public byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        update(input, inputOffset, inputLen);
        return doFinal();
    }

    @Override
    public int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                             byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException {
        int outputSize = engineGetOutputSize(buffer.size());
        if (outputSize > output.length - outputOffset) {
            throw new ShortBufferException(
                    "Need " + outputSize + " bytes for output");
        }

        update(input, inputOffset, inputLen);
        byte[] result = doFinal();
        int n = result.length;
        System.arraycopy(result, 0, output, outputOffset, n);
        Arrays.fill(result, (byte)0);
        return result.length;
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
        } finally {
            Arrays.fill(encoded, (byte)0);
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

    private void update(byte[] input, int inputOffset, int inputLen) {
        if (input == null || inputLen == 0) {
            return;
        }

        buffer.write(input, inputOffset, inputLen);
    }

    private byte[] doFinal() throws BadPaddingException, IllegalBlockSizeException {
        try {
            byte[] input = buffer.toByteArray();
            return encrypted ? sm2.encrypt(input) : sm2.decrypt(input);
        } finally {
            buffer.reset();
        }
    }

    @Override
    public AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    public byte[] engineGetIV() {
        return null;
    }

    @Override
    public int engineGetBlockSize() {
        return 0;
    }

    @Override
    public int engineGetOutputSize(int inputLen) {
        int offset = 1 + 2 * SM2_CURVE_FIELD_SIZE + SM3_DIGEST_LEN;
        return encrypted ? inputLen + offset
                : Math.max(0, inputLen - offset);
    }

    @Override
    public int engineGetKeySize(Key key) {
        return SM2_CURVE_FIELD_SIZE << 3;
    }
}
