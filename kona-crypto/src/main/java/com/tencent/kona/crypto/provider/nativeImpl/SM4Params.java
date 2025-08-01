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

import com.tencent.kona.crypto.CryptoUtils;

import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;

import static com.tencent.kona.crypto.util.Constants.SM4_GCM_IV_LEN;
import static com.tencent.kona.crypto.util.Constants.SM4_IV_LEN;

/**
 * The parameters for SM4 cipher.
 */
final class SM4Params {

    private final Mode mode;
    private final Padding padding;

    private final byte[] iv;

    public SM4Params(Mode mode, Padding padding, byte[] iv)
            throws InvalidAlgorithmParameterException {
        checkParams(mode, padding, iv);

        this.mode = mode;
        this.padding = padding;

        this.iv = CryptoUtils.clone(iv);
    }

    public SM4Params(Mode mode, Padding padding)
            throws InvalidAlgorithmParameterException {
        this(mode, padding, new byte[0]);
    }

    private void checkParams(Mode mode, Padding padding, byte[] iv)
            throws InvalidAlgorithmParameterException {
        if (mode == null) {
            throw new InvalidAlgorithmParameterException(
                    "Unsupported mode: " + mode);
        }

        switch(mode) {
            case ECB:
                checkECBParams(iv);
                break;

            case CBC:
                checkCBCParams(iv);
                break;

            case GCM:
                checkGCMParams(padding, iv);
                break;

            case CTR:
                checkCTRParams(padding, iv);
                break;

            default:
                throw new InvalidAlgorithmParameterException(
                        "Unsupported mode: " + mode);
        }
    }

    private void checkECBParams(byte[] iv)
            throws InvalidAlgorithmParameterException {
        checkIvNotNeeded(iv);
    }

    private void checkCBCParams(byte[] iv)
            throws InvalidAlgorithmParameterException {
        checkIvNeeded(iv, false);
    }

    private void checkGCMParams(Padding padding, byte[] iv)
            throws InvalidAlgorithmParameterException {
        checkPaddingNoNeeded(padding);
        checkIvNeeded(iv, true);
    }

    private void checkCTRParams(Padding padding, byte[] iv)
            throws InvalidAlgorithmParameterException {
        checkPaddingNoNeeded(padding);
        checkIvNeeded(iv, false);
    }

    private static void checkPaddingNoNeeded(Padding padding)
            throws InvalidAlgorithmParameterException {
        if (padding != Padding.NoPadding) {
            throw new InvalidAlgorithmParameterException(
                    "Padding is not supported");
        }
    }

    private static void checkIvNotNeeded(byte[] iv)
            throws InvalidAlgorithmParameterException {
        if (iv != null && iv.length > 0) {
            throw new InvalidAlgorithmParameterException("IV is not needed");
        }
    }

    private static void checkIvNeeded(byte[] iv, boolean isGCM)
            throws InvalidAlgorithmParameterException {
        if (iv == null || iv.length == 0) {
            throw new InvalidAlgorithmParameterException("IV is missing");
        }

        if (!isGCM && iv.length != SM4_IV_LEN) {
            throw new InvalidAlgorithmParameterException(
                    "The length of IV must be 16-bytes: " + iv.length);
        }

        if (isGCM && iv.length != SM4_GCM_IV_LEN) {
            throw new InvalidAlgorithmParameterException(
                    "The length of GCM IV must be 12-bytes: " + iv.length);
        }
    }

    public Mode mode() {
        return mode;
    }

    public Padding padding() {
        return padding;
    }

    public byte[] iv() {
        return iv.clone();
    }

    public void resetIV() {
        Arrays.fill(iv, (byte) 0);
    }
}
