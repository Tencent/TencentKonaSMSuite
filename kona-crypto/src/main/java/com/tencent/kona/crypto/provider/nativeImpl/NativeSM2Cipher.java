/*
 * Copyright (C) 2024, THL A29 Limited, a Tencent company. All rights reserved.
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

import javax.crypto.BadPaddingException;

import static com.tencent.kona.crypto.provider.nativeImpl.NativeCrypto.nativeCrypto;
import static com.tencent.kona.crypto.util.Constants.*;

/**
 * The SM2 cipher native implementation.
 */
final class NativeSM2Cipher extends NativeRef {

    // key can be private key, public key or even key pair.
    NativeSM2Cipher(byte[] key) {
        super(createCtx(key));
    }

    private static long createCtx(byte[] key) {
        checkKey(key);

        return nativeCrypto().sm2CipherCreateCtx(key);
    }

    private static void checkKey(byte[] key) {
        if (key == null || (
                key.length != SM2_PRIKEY_LEN &&
                key.length != SM2_PUBKEY_LEN &&
                key.length != (SM2_PRIKEY_LEN + SM2_PUBKEY_LEN))) {
            throw new IllegalStateException("Illegal key");
        }
    }

    public byte[] encrypt(byte[] plaintext) throws BadPaddingException {
        if (plaintext == null || plaintext.length == 0) {
            throw new BadPaddingException("Invalid plaintext");
        }

        byte[] ciphertext = nativeCrypto().sm2CipherEncrypt(pointer, plaintext);
        if (ciphertext == null) {
            throw new BadPaddingException("Encrypt failed");
        }
        return ciphertext;
    }

    public byte[] decrypt(byte[] ciphertext) throws BadPaddingException {
        if (ciphertext == null || ciphertext.length == 0) {
            throw new BadPaddingException("Invalid ciphertext");
        }

        byte[] cleartext = nativeCrypto().sm2CipherDecrypt(pointer, ciphertext);
        if (cleartext == null) {
            throw new BadPaddingException("Decrypt failed");
        }
        return cleartext;
    }

    @Override
    public void close() {
        nativeCrypto().sm2CipherFreeCtx(pointer);
        super.close();
    }
}
