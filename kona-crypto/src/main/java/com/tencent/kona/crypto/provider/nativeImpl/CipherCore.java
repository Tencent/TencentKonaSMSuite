/*
 * Copyright (C) 2022, 2024, Tencent. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. Tencent designates
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

import com.tencent.kona.sun.security.jca.JCAUtil;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;

import static com.tencent.kona.crypto.util.Constants.*;

final class CipherCore {

    private final byte[] buffer;

    private int buffered = 0;

    private Padding padding;

    private Mode cipherMode = Mode.ECB;

    private volatile AlgoCipher cipher;

    private boolean decrypting = false;

    private boolean requireReinit = false;
    private byte[] lastEncKey = null;
    private byte[] lastEncIv = null;

    private final SymmetricCipher rawImpl;

    CipherCore(SymmetricCipher impl) {
        rawImpl = impl;
        buffer = new byte[SM4_BLOCK_SIZE * 2];
    }

    void setMode(String mode) throws NoSuchAlgorithmException {
        Objects.requireNonNull(mode);

        String modeUpperCase = mode.toUpperCase(Locale.ENGLISH);

        if (modeUpperCase.equals("ECB")) {
            cipherMode = Mode.ECB;
        } else if (modeUpperCase.equals("CBC")) {
            cipherMode = Mode.CBC;
        } else if (modeUpperCase.equals("GCM")) {
            cipherMode = Mode.GCM;
        } else if (modeUpperCase.equals("CTR")) {
            cipherMode = Mode.CTR;
            padding = Padding.NoPadding;
        } else {
            throw new NoSuchAlgorithmException("Unknown mode: " + mode);
        }

        cipher = new AlgoCipher(rawImpl);
    }

    void setPadding(String paddingScheme) throws NoSuchPaddingException {
        if (paddingScheme == null) {
            throw new NoSuchPaddingException("null padding");
        }
        if (paddingScheme.equalsIgnoreCase("NOPADDING")) {
            padding = Padding.NoPadding;
        } else if (!paddingScheme.equalsIgnoreCase("PKCS7PADDING")) {
            throw new NoSuchPaddingException(
                    "Padding: " + paddingScheme + " not implemented");
        } else {
            if (cipherMode == Mode.CTR || cipherMode == Mode.GCM) {
                throw new NoSuchPaddingException(
                        "Padding: " + paddingScheme + " not supported");
            }
            padding = Padding.PKCS7Padding;
        }
    }

    int getOutputSize(int inputLen) {
        int totalLen = Math.addExact(buffered, inputLen);

        int incr = 0;
        if (!decrypting) {
            if (cipherMode == Mode.GCM) {
                incr = SM4_GCM_TAG_LEN;
            } else if (padding == Padding.PKCS7Padding) {
                incr = SM4_BLOCK_SIZE - totalLen % SM4_BLOCK_SIZE;
            }
        } else {
            if (cipherMode == Mode.GCM) {
                incr = - SM4_GCM_TAG_LEN;
            }
        }

        return Math.max(0, totalLen + incr);
    }

    byte[] getIV() {
        return cipher.getIV();
    }

    AlgorithmParameters getParameters(String algName, String provider) {
        if (cipherMode == Mode.ECB) {
            return null;
        }

        AlgorithmParameters params;
        AlgorithmParameterSpec paramSpec;
        byte[] iv = getIV();
        if (iv == null) {
            iv = new byte[SM4_IV_LEN];
            JCAUtil.getSecureRandom().nextBytes(iv);
        }
        if (cipherMode == Mode.GCM) {
            paramSpec = new GCMParameterSpec(SM4_GCM_TAG_LEN * 8, iv);
        } else {
            paramSpec = new IvParameterSpec(iv);
        }
        try {
            if (provider != null) {
                params = AlgorithmParameters.getInstance("SM4", provider);
            } else {
                params = AlgorithmParameters.getInstance("SM4");
            }
            params.init(paramSpec);
        } catch (NoSuchAlgorithmException nsae) {
            throw new RuntimeException("Cannot find " + algName +
                    " AlgorithmParameters implementation in SMCS provider");
        } catch (InvalidParameterSpecException ipse) {
            throw new RuntimeException(paramSpec.getClass() + " not supported");
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Cannot find SMCS provider", e);
        }
        return params;
    }

    AlgorithmParameters getParameters(String algName) {
        return getParameters(algName, null);
    }

    void init(int opmode, Key key, SecureRandom random)
            throws InvalidKeyException {
        try {
            init(opmode, key, (AlgorithmParameterSpec)null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException(e.getMessage());
        }
    }

    void init(int opmode,
              Key key,
              AlgorithmParameterSpec paramSpec,
              SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        decrypting = (opmode == Cipher.DECRYPT_MODE)
                || (opmode == Cipher.UNWRAP_MODE);

        byte[] keyBytes = getKeyBytes(key);
        byte[] iv = null;
        if (paramSpec != null) {
            if (cipherMode == Mode.GCM) {
                if (paramSpec instanceof GCMParameterSpec) {
                    int tagLenBits = ((GCMParameterSpec) paramSpec).getTLen();
                    if (tagLenBits != SM4_GCM_TAG_LEN * 8) {
                        throw new InvalidAlgorithmParameterException(
                                "The length of GCM Tag must be 16-bytes.");
                    }
                    iv = ((GCMParameterSpec) paramSpec).getIV();
                } else {
                    throw new InvalidAlgorithmParameterException(
                            "Unsupported parameter: " + paramSpec);
                }
            } else {
                if (paramSpec instanceof IvParameterSpec) {
                    iv = ((IvParameterSpec) paramSpec).getIV();
                } else {
                    throw new InvalidAlgorithmParameterException(
                            "Unsupported parameter: " + paramSpec);
                }
            }
        }

        if (cipherMode == Mode.ECB) {
            if (iv != null) {
                throw new InvalidAlgorithmParameterException(
                        "ECB mode cannot use IV");
            }
        } else if (iv == null)  {
            if (decrypting) {
                throw new InvalidAlgorithmParameterException(
                        "Parameters IV for decrypting missing must be set with SetParameter()");
            }

            iv = new byte[SM4_IV_LEN];
            if (random != null) {
                random.nextBytes(iv);
            } else {
                JCAUtil.getSecureRandom().nextBytes(iv);
            }
        }

        buffered = 0;

        if (cipherMode == Mode.GCM) {
            if (!decrypting) {
                requireReinit = Arrays.equals(iv, lastEncIv)
                        && MessageDigest.isEqual(keyBytes, lastEncKey);
                if (requireReinit) {
                    throw new InvalidAlgorithmParameterException(
                            "Cannot reuse IV for GCM mode");
                }
                lastEncIv = iv;
                lastEncKey = keyBytes;
            }
        }

        SM4Params sm4ParamSpec = new SM4Params(cipherMode, padding, iv);
        cipher.init(decrypting, key.getAlgorithm(), keyBytes, sm4ParamSpec);

        requireReinit = false;
    }

    void init(int opmode, Key key, AlgorithmParameters params,
              SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec spec = null;
        if (params != null) {
            try {
                if (cipherMode == Mode.GCM) {
                    spec = params.getParameterSpec(GCMParameterSpec.class);
                } else {
                    spec = params.getParameterSpec(IvParameterSpec.class);
                }
            } catch (InvalidParameterSpecException ipse) {
                throw new InvalidAlgorithmParameterException("Wrong parameter type");
            }
        }
        init(opmode, key, spec, random);
    }

    static byte[] getKeyBytes(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("No key given");
        }
        if (!"RAW".equalsIgnoreCase(key.getFormat())) {
            throw new InvalidKeyException("Wrong format: RAW bytes needed");
        }
        byte[] keyBytes = key.getEncoded();
        if (keyBytes == null) {
            throw new InvalidKeyException("RAW key bytes missing");
        }
        return keyBytes;
    }

    byte[] update(byte[] input, int inputOffset, int inputLen) {
        checkReinit();

        byte[] data = !decrypting ? cipher.encrypt(input, inputOffset, inputLen)
                : cipher.decrypt(input, inputOffset, inputLen);

        buffered = buffered(buffered, inputLen, data.length);

        return data;
    }

    int update(byte[] input, int inputOffset, int inputLen,
               byte[] output, int outputOffset)
            throws ShortBufferException {
        checkReinit();

        byte[] data = !decrypting ? cipher.encrypt(input, inputOffset, inputLen)
                : cipher.decrypt(input, inputOffset, inputLen);

        buffered = buffered(buffered, inputLen, data.length);

        System.arraycopy(data, 0, output, outputOffset, data.length);
        return data.length;
    }

    private int buffered(int origBuffered, int inputLen, int outputLen) {
        int buffered = 0;

        // TODO not care decrypting
        if (decrypting) {
            return buffered;
        }

        if (outputLen == 0) {
            buffered = Math.addExact(origBuffered, inputLen);
        } else {
            buffered = Math.subtractExact(
                    Math.addExact(origBuffered, inputLen),
                    outputLen);
        }

        return buffered;
    }

    byte[] doFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException {
        try {
            checkReinit();

            byte[] output = new byte[getOutputSize(inputLen)];
            byte[] finalBuf = prepareInputBuffer(input, inputOffset,
                    inputLen, output, 0);

            int finalOffset = (finalBuf == input) ? inputOffset : 0;
            int finalBufLen = (finalBuf == input) ? inputLen : finalBuf.length;

            byte[] ot = encDecOutput(finalBuf, finalOffset, finalBufLen);

            endDoFinal();
            return ot;
        } catch (ShortBufferException e) {
            throw new ProviderException("Unexpected exception", e);
        }
    }

    int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
                int outputOffset)
            throws IllegalBlockSizeException, ShortBufferException {

        byte[] out = doFinal(input, inputOffset, inputLen);
        int len = Math.min(out.length, output.length - outputOffset);
        System.arraycopy(out, 0, output, outputOffset, len);
        return len;
    }

    private byte[] prepareInputBuffer(byte[] input, int inputOffset,
                                      int inputLen, byte[] output,
                                      int outputOffset)
            throws IllegalBlockSizeException, ShortBufferException {
        // calculate total input length
        int len = Math.addExact(buffered, inputLen);
        if (len == 0) {
            // no work to do.
            // TSM XXXFinal() methods don't accept any more input data.
            return new byte[0];
        }

        if (padding == Padding.NoPadding) {
            if ((cipherMode != Mode.GCM)
                    && (cipherMode != Mode.CTR) && ((len % SM4_BLOCK_SIZE) != 0)) {
                throw new IllegalBlockSizeException(
                        "Input size is not multiple of block size: " + len);
            }
        }

        if (buffered != 0 || !decrypting || (input == output
                && (outputOffset - inputOffset < inputLen)
                && (inputOffset - outputOffset < buffer.length))) {
            byte[] finalBuf;
            finalBuf = new byte[len];
            if (buffered != 0) {
                System.arraycopy(buffer, 0, finalBuf, 0, buffered);
                if (!decrypting) {
                    // Clean the ciphertext
                    Arrays.fill(buffer, (byte) 0x00);
                }
            }
            if (inputLen != 0) {
                System.arraycopy(input, inputOffset, finalBuf,
                        buffered, inputLen);
            }
            return finalBuf;
        }
        return input;
    }

    private void endDoFinal() {
        buffered = 0;
        if (cipherMode != Mode.ECB) {
            cipher.reset();
        }
    }

    private void checkReinit() {
        if (requireReinit) {
            throw new IllegalStateException(
                    "Must use either different key or iv for GCM encryption");
        }
    }

    private byte[] encDecOutput(byte[] in, int inOfs, int len)
            throws IllegalBlockSizeException, ShortBufferException {
        if (cipherMode != Mode.GCM && cipherMode != Mode.CTR && (len % SM4_BLOCK_SIZE != 0)) {
            if (padding == Padding.NoPadding) {
                throw new IllegalBlockSizeException(
                        "Input length is not multiple of " + SM4_BLOCK_SIZE + " bytes");
            }
        }

        return !decrypting ? cipher.encryptFinal(in, inOfs, len)
                : cipher.decryptFinal(in, inOfs, len);
    }

    byte[] wrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        byte[] encodedKey = key.getEncoded();
        if ((encodedKey == null) || (encodedKey.length == 0)) {
            throw new InvalidKeyException("No encoded key");
        }

        return doFinal(encodedKey, 0, encodedKey.length);
    }

    Key unwrap(byte[] wrappedKey, String wrappedKeyAlgorithm,
               int wrappedKeyType)
            throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] encodedKey;
        try {
            encodedKey = doFinal(wrappedKey, 0, wrappedKey.length);
        } catch (IllegalBlockSizeException e) {
            throw new InvalidKeyException("The wrapped key is invalid", e);
        }
        return ConstructKeys.constructKey(encodedKey, wrappedKeyAlgorithm,
                wrappedKeyType);
    }

    void updateAAD(byte[] src, int offset, int len) {
        checkReinit();
        cipher.updateAAD(src, offset, len);
    }
}
