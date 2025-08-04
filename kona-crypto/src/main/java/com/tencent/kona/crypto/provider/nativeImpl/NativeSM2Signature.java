/*
 * Copyright (C) 2024, Tencent. All rights reserved.
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

import javax.crypto.BadPaddingException;

import static com.tencent.kona.crypto.provider.nativeImpl.NativeCrypto.*;
import static com.tencent.kona.crypto.util.Constants.*;

/**
 * The SM2 signature native implementation.
 */
final class NativeSM2Signature extends NativeRef {

    NativeSM2Signature(byte[] priKey, byte[] pubKey, byte[] id, boolean isSign) {
        super(createCtx(priKey, pubKey, id, isSign));
    }

    NativeSM2Signature(byte[] pubKey, byte[] id, boolean isSign) {
        this(null, pubKey, id, isSign);
    }

    private static long createCtx(byte[] priKey, byte[] pubKey, byte[] id, boolean isSign) {
        checkKey(priKey, pubKey, isSign);
        checkId(id);

        int keySize = priKey == null ? 0 : priKey.length;
        keySize += pubKey == null ? 0 : pubKey.length;
        byte[] key = new byte[keySize];
        if (priKey != null) {
            System.arraycopy(priKey, 0, key, 0, priKey.length);
            if (pubKey != null) {
                System.arraycopy(pubKey, 0, key, priKey.length, pubKey.length);
            }
        } else {
            System.arraycopy(pubKey, 0, key, 0, pubKey.length);
        }

        return nativeCrypto().sm2SignatureCreateCtx(key, id, isSign);
    }

    private static void checkKey(byte[] priKey, byte[] pubKey, boolean isSign) {
        if (isSign) {
            if (priKey == null || priKey.length != SM2_PRIKEY_LEN) {
                throw new IllegalStateException("Invalid private key");
            }
        } else {
            if (priKey != null || pubKey == null || pubKey.length != SM2_PUBKEY_LEN) {
                throw new IllegalStateException("Invalid public key");
            }
        }
    }

    private static void checkId(byte[] id) {
        if (id == null || id.length == 0) {
            throw new IllegalStateException("Illegal ID");
        }
    }

    public byte[] sign(byte[] message) throws BadPaddingException {
        if (message == null) {
            throw new BadPaddingException("Message cannot be null");
        }

        byte[] signature = pointer == 0
                ? null
                : nativeCrypto().sm2SignatureSign(pointer, message);
        if (signature == null) {
            throw new BadPaddingException("Sign failed");
        }
        return signature;
    }

    public boolean verify(byte[] message, byte[] signature) throws BadPaddingException {
        if (message == null) {
            throw new BadPaddingException("Message cannot be null");
        }

        if (signature == null || signature.length == 0) {
            throw new BadPaddingException("Invalid signature");
        }

        int verified = pointer == 0
                ? OPENSSL_FAILURE
                : nativeCrypto().sm2SignatureVerify(pointer, message, signature);
        return verified == OPENSSL_SUCCESS;
    }

    @Override
    public void close() {
        if (pointer != 0) {
            nativeCrypto().sm2SignatureFreeCtx(pointer);
            super.close();
        }
    }
}
