/*
 * Copyright (c) 2012, 2023, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.util.Constants;

import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

import com.tencent.kona.jdk.internal.misc.SharedSecretsUtil;
import com.tencent.kona.sun.security.jca.JCAUtil;
import com.tencent.kona.sun.security.util.PBEUtil;

/**
 * This class represents password-based encryption as defined by the PKCS #5
 * standard.
 * These algorithms implement PBE with HmacSHA1/HmacSHA2-family and AES-CBC.
 * Padding is done as described in PKCS #5.
 *
 * @author Jan Luehe
 *
 *
 * @see javax.crypto.Cipher
 */
abstract class PBES2Core extends CipherSpi {

    // the encapsulated cipher
    private final CipherCore cipher;
    private final int keyLength; // in bits
    private final int blkSize; // in bits
    private final PBKDF2Core kdf;
    private final String pbeAlgo;
    private final String cipherAlgo;
    private final PBEUtil.PBES2Params pbes2Params = new PBEUtil.PBES2Params();

    /**
     * Creates an instance of PBE Scheme 2 according to the selected
     * password-based key derivation function and encryption scheme.
     */
    PBES2Core(String kdfAlgo, String cipherAlgo, int keySize)
        throws NoSuchAlgorithmException, NoSuchPaddingException {

        this.cipherAlgo = cipherAlgo;
        keyLength = keySize * 8;
        if ("SM4".equalsIgnoreCase(cipherAlgo)) {
            pbeAlgo = "PBEWith" + kdfAlgo + "And" + cipherAlgo;
        } else {
            pbeAlgo = "PBEWith" + kdfAlgo + "And" + cipherAlgo + "_" + keyLength;
        }

        if ("SM4".equalsIgnoreCase(cipherAlgo)) {
            blkSize = Constants.SM4_BLOCK_SIZE;
            cipher = new CipherCore(new SM4Crypt(), blkSize);

            switch(kdfAlgo) {
            case "HmacSM3":
                kdf = new PBKDF2Core.HmacSM3();
                break;
            default:
                throw new NoSuchAlgorithmException(
                    "No Cipher implementation for " + kdfAlgo);
            }
        } else {
            throw new NoSuchAlgorithmException("No Cipher implementation for " +
                                               pbeAlgo);
        }
        cipher.setMode("CBC");
        cipher.setPadding("PKCS5Padding");
    }

    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if ((mode != null) && (!mode.equalsIgnoreCase("CBC"))) {
            throw new NoSuchAlgorithmException("Invalid cipher mode: " + mode);
        }
    }

    protected void engineSetPadding(String paddingScheme)
        throws NoSuchPaddingException {
        if ((paddingScheme != null) &&
            (!paddingScheme.equalsIgnoreCase("PKCS5Padding"))) {
            throw new NoSuchPaddingException("Invalid padding scheme: " +
                                             paddingScheme);
        }
    }

    protected int engineGetBlockSize() {
        return blkSize;
    }

    protected int engineGetOutputSize(int inputLen) {
        return cipher.getOutputSize(inputLen);
    }

    protected byte[] engineGetIV() {
        return cipher.getIV();
    }

    protected AlgorithmParameters engineGetParameters() {
        return pbes2Params.getAlgorithmParameters(
                blkSize, pbeAlgo, JCAUtil.getSecureRandom());
    }

    protected void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException ie) {
            throw new InvalidKeyException("requires PBE parameters", ie);
        }
    }

    protected void engineInit(int opmode, Key key,
                              AlgorithmParameterSpec params,
                              SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {

        PBEKeySpec pbeSpec = pbes2Params.getPBEKeySpec(blkSize, keyLength,
                opmode, key, params, random);
        PBKDF2KeyImpl s = null;
        byte[] derivedKey;

        try {
            s = (PBKDF2KeyImpl)kdf.engineGenerateSecret(pbeSpec);
            derivedKey = s.getEncoded();
        } catch (InvalidKeySpecException ikse) {
            throw new InvalidKeyException("Cannot construct PBE key", ikse);
        } finally {
            if (s != null) {
                s.clear();
            }
            pbeSpec.clearPassword();
        }
        SecretKeySpec cipherKey = null;
        try {
            cipherKey = new SecretKeySpec(derivedKey, cipherAlgo);
            // initialize the underlying cipher
            cipher.init(opmode, cipherKey, pbes2Params.getIvSpec(), random);
        } finally {
            if (cipherKey != null) {
                SharedSecretsUtil.cryptoSpecClearSecretKeySpec(cipherKey);
            }
            Arrays.fill(derivedKey, (byte) 0);
        }
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameters params,
                              SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, PBEUtil.PBES2Params.getParameterSpec(params),
                random);
    }

    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        return cipher.update(input, inputOffset, inputLen);
    }

    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                               byte[] output, int outputOffset)
        throws ShortBufferException {
        return cipher.update(input, inputOffset, inputLen,
                             output, outputOffset);
    }

    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
        throws IllegalBlockSizeException, BadPaddingException {
        return cipher.doFinal(input, inputOffset, inputLen);
    }

    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                                byte[] output, int outputOffset)
        throws ShortBufferException, IllegalBlockSizeException,
               BadPaddingException {
        return cipher.doFinal(input, inputOffset, inputLen,
                              output, outputOffset);
    }

    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        return keyLength;
    }

    protected byte[] engineWrap(Key key)
        throws IllegalBlockSizeException, InvalidKeyException {
        return cipher.wrap(key);
    }

    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm,
                               int wrappedKeyType)
        throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] encodedKey;
        return cipher.unwrap(wrappedKey, wrappedKeyAlgorithm,
                             wrappedKeyType);
    }

    public static final class HmacSM3AndSM4 extends PBES2Core {
        public HmacSM3AndSM4()
                throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("HmacSM3", "SM4", 16);
        }
    }
}
