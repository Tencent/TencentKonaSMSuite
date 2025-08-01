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

import java.security.SignatureException;

import static com.tencent.kona.crypto.provider.nativeImpl.NativeCrypto.*;

public class NativeECDSASignature extends NativeRef {

    NativeECDSASignature(int mdNID, int curveNID, byte[] key, boolean isSign) {
        super(createCtx(mdNID, curveNID, key, isSign));
    }

    private static long createCtx(
            int mdNID, int curveNID, byte[] key, boolean isSign) {
        if (key == null || key.length == 0) {
            throw new IllegalStateException("Key is null or empty");
        }

        return ecdsaCreateCtx(mdNID, curveNID, key, isSign);
    }

    public byte[] sign(byte[] message) throws SignatureException {
        if (message == null) {
            throw new SignatureException("Message cannot be null");
        }

        byte[] signature = pointer == 0
                ? null
                : NativeCrypto.ecdsaSign(pointer, message);
        if (signature == null) {
            throw new SignatureException("Sign failed");
        }
        return signature;
    }

    public boolean verify(byte[] message, byte[] signature)
            throws SignatureException {
        if (message == null) {
            throw new SignatureException("Message cannot be null");
        }

        if (signature == null || signature.length == 0) {
            throw new SignatureException("Invalid signature");
        }

        int verified = pointer == 0
                ? OPENSSL_FAILURE
                : NativeCrypto.ecdsaVerify(pointer, message, signature);
        return verified == OPENSSL_SUCCESS;
    }

    @Override
    public void close() {
        if (pointer != 0) {
            ecdsaFreeCtx(pointer);
            super.close();
        }
    }
}
