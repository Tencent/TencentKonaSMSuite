/*
 * Copyright (C) 2024, Tencent. All rights reserved.
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

import static com.tencent.kona.crypto.provider.nativeImpl.NativeCrypto.nativeCrypto;

/**
 * The SM2 key agreement native implementation.
 */
public class NativeSM2KeyAgreement extends NativeRef {

    NativeSM2KeyAgreement() {
        super(createCtx());
    }

    private static long createCtx() {
        return nativeCrypto().sm2KeyExCreateCtx();
    }

    public byte[] deriveKey(byte[] priKey, byte[] pubKey, byte[] ePriKey, byte[] id,
            byte[] peerPubKey, byte[] peerEPubKey, byte[] peerId,
            boolean isInitiator, int sharedKeyLength) throws IllegalStateException {
        if (priKey == null || priKey.length == 0 ||
            pubKey == null || pubKey.length == 0 ||
            ePriKey == null || ePriKey.length == 0 ||
            id == null || id.length == 0 ||
            peerPubKey == null || peerPubKey.length == 0 ||
            peerEPubKey == null || peerEPubKey.length == 0 ||
            peerId == null || peerId.length == 0) {
            throw new IllegalStateException("Cannot generate shared key");
        }

        if (sharedKeyLength <= 0) {
            throw new IllegalStateException("Shared key length must be greater than 0");
        }

        byte[] sharedKey = pointer == 0 ? null : nativeCrypto().sm2DeriveKey(pointer,
                priKey, pubKey, ePriKey, id,
                peerPubKey, peerEPubKey, peerId,
                isInitiator, sharedKeyLength);
        if (sharedKey == null) {
            throw new IllegalStateException("Cannot generate shared key");
        }
        return sharedKey;
    }

    @Override
    public void close() {
        if (pointer != 0) {
            nativeCrypto().sm2KeyExFreeCtx(pointer);
            super.close();
        }
    }
}
