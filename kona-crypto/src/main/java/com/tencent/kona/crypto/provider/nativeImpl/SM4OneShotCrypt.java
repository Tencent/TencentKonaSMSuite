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

import com.tencent.kona.crypto.util.RangeUtil;
import com.tencent.kona.crypto.CryptoUtils;

import javax.crypto.AEADBadTagException;
import java.security.InvalidKeyException;

import static com.tencent.kona.crypto.util.Constants.*;

class SM4OneShotCrypt extends SymmetricCipher {

    private boolean opChanged = false;
    private boolean decrypting = false;
    private SM4Params paramSpec;
    private byte[] key;

    private NativeSM4 sm4;

    private DataWindow gcmLastCipherBlock;

    @Override
    int getBlockSize() {
        return SM4_BLOCK_SIZE;
    }

    @Override
    void init(boolean decrypting,
              String algorithm,
              byte[] key,
              SM4Params paramSpec)
            throws InvalidKeyException {
        this.paramSpec = null;
        this.key = null;
        this.gcmLastCipherBlock = null;

        this.sm4 = null;

        if (!"SM4".equalsIgnoreCase(algorithm)) {
            throw new InvalidKeyException(
                    "Wrong algorithm: expected SM4, actual: " + algorithm);
        }

        if (key.length != SM4_KEY_SIZE) {
            throw new InvalidKeyException(
                    "Wrong key size: expected 16-byte, actual " + key.length);
        }

        this.opChanged = this.decrypting != decrypting;
        this.decrypting = decrypting;
        this.paramSpec = paramSpec;
        this.key = key;

        init();
    }

    private void init() {
        Mode mode = paramSpec.mode();
        boolean padding = paramSpec.padding() == Padding.PKCS7Padding;
        byte[] iv = paramSpec.iv();

        switch (mode) {
            case ECB:
                sm4 = new NativeSM4.SM4ECB(!decrypting, padding, key);
                break;
            case CBC:
                sm4 = new NativeSM4.SM4CBC(!decrypting, padding, key, iv);
                break;
            case GCM:
                gcmLastCipherBlock = new DataWindow(SM4_GCM_TAG_LEN);
                if (sm4 == null || opChanged) {
                    sm4 = new NativeSM4.SM4GCM(!decrypting, key, iv);
                } else {
                    ((NativeSM4.SM4GCM) sm4).setIV(iv);
                }
                break;
            case CTR:
                sm4 = new NativeSM4.SM4CTR(!decrypting, key, iv);
                break;
            default:
                throw new IllegalStateException("Unexpected mode: " + mode);
        }
    }

    @Override
    SM4Params getParamSpec() {
        return paramSpec;
    }

    void updateAAD(byte[] aad) {
        if (isMode(Mode.GCM)) {
            NativeSM4.SM4GCM sm4GCM = (NativeSM4.SM4GCM) sm4;
            sm4GCM.updateAAD(aad);
        }
    }

    @Override
    byte[] encryptBlock(byte[] plaintext, int offset, int length) {
        return update(plaintext, offset, length);
    }

    @Override
    byte[] decryptBlock(byte[] ciphertext, int offset, int length) {
        byte[] bufCiphertext = ciphertext;
        int bufOffset = offset;
        int bufLength = length;

        if (isMode(Mode.GCM)) {
            bufCiphertext = gcmLastCipherBlock.put(
                    bufCiphertext, bufOffset, bufLength);
            bufOffset = 0;
            bufLength = bufCiphertext.length;
        }

        return update(bufCiphertext, bufOffset, bufLength);
    }

    private byte[] update(byte[] input, int offset, int length) {
        RangeUtil.nullAndBoundsCheck(input, offset, length);

        byte[] data = CryptoUtils.copy(input, offset, length);
        if (sm4 instanceof NativeSM4.SM4ECB) {
            NativeSM4.SM4ECB sm4ecb = (NativeSM4.SM4ECB) sm4;
            return sm4ecb.update(data);
        } else if (sm4 instanceof NativeSM4.SM4CBC) {
            NativeSM4.SM4CBC sm4cbc = (NativeSM4.SM4CBC) sm4;
            return sm4cbc.update(data);
        } else if (sm4 instanceof NativeSM4.SM4GCM) {
            NativeSM4.SM4GCM sm4gcm = (NativeSM4.SM4GCM) sm4;
            return sm4gcm.update(data);
        } else if (sm4 instanceof NativeSM4.SM4CTR) {
            NativeSM4.SM4CTR sm4ctr = (NativeSM4.SM4CTR) sm4;
            return sm4ctr.update(data);
        }

        throw new IllegalStateException("Unexpected SM4: " + sm4.getClass());
    }

    @Override
    byte[] encryptBlockFinal(byte[] plaintext, int offset, int length) {
        try {
            return doFinal(plaintext, offset, length);
        } finally {
            sm4.close();
            sm4 = null;
        }
    }

    @Override
    byte[] decryptBlockFinal(byte[] ciphertext, int offset, int length) {
        try {
            return doFinal(ciphertext, offset, length);
        } finally {
            sm4.close();
            sm4 = null;
        }
    }

    private byte[] doFinal(byte[] input, int offset, int length) {
        RangeUtil.nullAndBoundsCheck(input, offset, length);

        byte[] data = CryptoUtils.copy(input, offset, length);
        byte[] updateOut;
        byte[] finalOut = new byte[0];
        if (sm4 instanceof NativeSM4.SM4ECB) {
            NativeSM4.SM4ECB sm4ecb = (NativeSM4.SM4ECB) sm4;
            updateOut = sm4ecb.update(data);
            finalOut = sm4ecb.doFinal();
        } else if (sm4 instanceof NativeSM4.SM4CBC) {
            NativeSM4.SM4CBC sm4cbc = (NativeSM4.SM4CBC) sm4;
            updateOut = sm4cbc.update(data);
            finalOut = sm4cbc.doFinal();
        }  else if (sm4 instanceof NativeSM4.SM4GCM) {
            NativeSM4.SM4GCM sm4gcm = (NativeSM4.SM4GCM) sm4;

            if (!decrypting) {
                updateOut = sm4gcm.update(data);

                // Generate the tag
                sm4gcm.doFinal();
                finalOut = sm4gcm.getTag();
            } else {
                byte[] finalCiphertext = gcmLastCipherBlock.put(data);
                updateOut = sm4gcm.update(finalCiphertext);

                byte[] tag = gcmLastCipherBlock.data();
                if (tag.length != SM4_GCM_TAG_LEN) {
                    throw new IllegalStateException(
                            new AEADBadTagException(String.format(
                                    "The tag must be %s-bytes: %d",
                                    SM4_GCM_TAG_LEN, tag.length)));
                }

                // Verify the tag
                sm4gcm.setTag(tag);
                sm4gcm.doFinal();
            }
        } else if (sm4 instanceof NativeSM4.SM4CTR) {
            NativeSM4.SM4CTR sm4ctr = (NativeSM4.SM4CTR) sm4;
            updateOut = sm4ctr.update(data);
            sm4ctr.doFinal();
        } else {
            throw new IllegalStateException(
                    "Unexpected SM4: " + sm4.getClass());
        }

        return CryptoUtils.concat(updateOut, finalOut);
    }

    private boolean isMode(Mode mode) {
        return getParamSpec().mode() == mode;
    }
}
