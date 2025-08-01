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

import com.tencent.kona.crypto.CryptoUtils;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

class AlgoCipher {

    enum State {
        NOT_INIT, INIT, UPDATED, FINAL
    }

    private final SymmetricCipher embeddedCipher;

    private State state = State.NOT_INIT;

    AlgoCipher(SymmetricCipher embeddedCipher) {
        this.embeddedCipher = embeddedCipher;
    }

    final SymmetricCipher getEmbeddedCipher() {
        return embeddedCipher;
    }

    final State state() {
        return state;
    }

    final int getBlockSize() {
        return embeddedCipher.getBlockSize();
    }

    final SM4Params getParamSpec() {
        return embeddedCipher.getParamSpec();
    }

    final byte[] getIV() {
        return getParamSpec().iv();
    }

    void init(boolean decrypting, String algorithm, byte[] key,
              SM4Params paramSpec)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        state = State.INIT;
        embeddedCipher.init(decrypting, algorithm, key, paramSpec);
    }

    void reset() { }

    byte[] encrypt(byte[] plain, int plainOffset, int plainLen) {
        state = State.UPDATED;
        return embeddedCipher.encryptBlock(plain, plainOffset, plainLen);
    }

    byte[] encryptFinal(byte[] plain, int plainOffset, int plainLen) {
        state = State.FINAL;
        return embeddedCipher.encryptBlockFinal(plain, plainOffset, plainLen);
    }

    byte[] decrypt(byte[] cipher, int cipherOffset, int cipherLen) {
        state = State.UPDATED;
        return embeddedCipher.decryptBlock(cipher, cipherOffset, cipherLen);
    }

    byte[] decryptFinal(byte[] cipher, int cipherOffset, int cipherLen) {
        state = State.FINAL;
        return embeddedCipher.decryptBlockFinal(cipher, cipherOffset, cipherLen);
    }

    // Only used by GCM mode
    void updateAAD(byte[] src, int offset, int len) {
        checkState();
        getEmbeddedCipher().updateAAD(CryptoUtils.copy(src, offset, len));
    }

    private void checkState() {
        State state = state();

        if (state == State.NOT_INIT) {
            throw new IllegalStateException("Cipher is not initialized yet");
        }

        if (state == State.UPDATED || state == State.FINAL) {
            throw new IllegalStateException(
                    "update/doFinal was called, so cannot accept more AAD.");
        }
    }
}
