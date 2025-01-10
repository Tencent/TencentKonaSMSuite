/*
 * Copyright (C) 2024, 2025, THL A29 Limited, a Tencent company. All rights reserved.
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

import static com.tencent.kona.crypto.provider.nativeImpl.NativeCrypto.nativeCrypto;

import static com.tencent.kona.crypto.util.Constants.*;

/**
 * The SM2 key pair generation native implementation.
 */
final class NativeSM2KeyPairGen extends NativeRef {

    NativeSM2KeyPairGen() {
        super(createCtx());
    }

    private static long createCtx() {
        return nativeCrypto().sm2KeyPairGenCreateCtx();
    }

    // Format: K || 0x04 || X || Y, 97-bytes
    // K is the private key, 32-bytes
    // X and Y are the coordinates of the public key, 32-bytes
    public byte[] genKeyPair() {
        byte[] keyPair = pointer == 0
                ? null
                : nativeCrypto().sm2KeyPairGenGenKeyPair(pointer);
        if (keyPair == null) {
            throw new IllegalStateException("Generate key pair failed");
        }

        if (keyPair.length == SM2_PRIKEY_LEN + SM2_PUBKEY_LEN) {
            return keyPair;
        } else if (keyPair.length == SM2_PRIKEY_LEN + SM2_COMP_PUBKEY_LEN) {
            // Convert the compressed public key to the uncompressed
            byte[] uncompPubKey = NativeCrypto.sm2ToUncompPubKey(
                    CryptoUtils.copy(keyPair, SM2_PRIKEY_LEN, SM2_COMP_PUBKEY_LEN));
            byte[] uncompKeyPair = new byte[SM2_PRIKEY_LEN + SM2_PUBKEY_LEN];
            System.arraycopy(keyPair, 0, uncompKeyPair, 0, SM2_PRIKEY_LEN);
            System.arraycopy(uncompPubKey, 0, uncompKeyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);
            return uncompKeyPair;
        }

        throw new IllegalStateException("Illegal key pair");
    }

    @Override
    public void close() {
        if (pointer != 0) {
            nativeCrypto().sm2KeyPairGenFreeCtx(pointer);
            super.close();
        }
    }
}
