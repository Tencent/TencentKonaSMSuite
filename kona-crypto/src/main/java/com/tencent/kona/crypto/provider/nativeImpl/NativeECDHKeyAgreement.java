/*
 * Copyright (C) 2025, Tencent. All rights reserved.
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

import static com.tencent.kona.crypto.provider.nativeImpl.NativeCrypto.*;

public class NativeECDHKeyAgreement extends NativeRef {

    NativeECDHKeyAgreement(int curveNID, byte[] priKey) {
        super(createCtx(curveNID, priKey));
    }

    private static long createCtx(int curveNID, byte[] priKey) {
        if (priKey == null || priKey.length == 0) {
            throw new IllegalStateException("Private key is null or empty");
        }

        return ecdhCreateCtx(curveNID, priKey);
    }

    public byte[] deriveKey(byte[] pubKey) {
        if (pubKey == null || pubKey.length == 0) {
            throw new IllegalStateException("Public key cannot be null");
        }

        byte[] sharedKey = pointer == 0 ? null : ecdhDeriveKey(pointer, pubKey);
        if (sharedKey == null) {
            throw new IllegalStateException("Derive key failed");
        }
        return sharedKey;
    }

    @Override
    public void close() {
        if (pointer != 0) {
            ecdhFreeCtx(pointer);
            super.close();
        }
    }
}
