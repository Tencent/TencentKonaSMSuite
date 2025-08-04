/*
 * Copyright (C) 2025, Tencent. All rights reserved.
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

import static com.tencent.kona.crypto.provider.nativeImpl.NativeCrypto.*;

public class NativeECKeyPairGen extends NativeRef {

    private final int curveNID;

    NativeECKeyPairGen(int curveNID) {
        super(createCtx(curveNID));
        this.curveNID = curveNID;
    }

    private static long createCtx(int curveNID) {
        return ecKeyPairGenCreateCtx(curveNID);
    }

    // Object[0]: private key value, byte array
    // Object[1]: uncompressed public key point, byte array
    public Object[] genKeyPair() {
        Object[] keyPair = pointer == 0
                ? null
                : ecKeyPairGenGenKeyPair(pointer, curveNID);
        if (keyPair == null) {
            throw new IllegalStateException("Generate key pair failed");
        }

        return keyPair;
    }

    @Override
    public void close() {
        if (pointer != 0) {
            ecKeyPairGenFreeCtx(pointer);
            super.close();
        }
    }
}
