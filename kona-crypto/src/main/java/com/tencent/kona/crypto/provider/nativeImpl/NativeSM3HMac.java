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

import com.tencent.kona.crypto.util.Sweeper;

import java.util.Objects;

import static com.tencent.kona.crypto.provider.nativeImpl.NativeCrypto.*;

/**
 * The SM3 HMAC native implementation.
 */
final class NativeSM3HMac extends NativeRef implements Cloneable {

    private static final Sweeper SWEEPER = Sweeper.instance();

    public NativeSM3HMac(byte[] key) {
        super(createCtx(key));
    }

    private static long createCtx(byte[] key) {
        if (key == null || key.length == 0) {
            throw new IllegalStateException("Key must not be null or empty");
        }

        return nativeCrypto().sm3hmacCreateCtx(key);
    }

    public NativeSM3HMac(long pointer) {
        super(pointer);
    }

    public void update(byte[] data) {
        Objects.requireNonNull(data);

        if (pointer == 0
                || nativeCrypto().sm3hmacUpdate(pointer, data) != OPENSSL_SUCCESS) {
            throw new IllegalStateException("SM3Hmac update operation failed");
        }
    }

    public byte[] doFinal() {
        byte[] result = pointer == 0
                ? null
                : nativeCrypto().sm3hmacFinal(pointer);
        if (result == null) {
            throw new IllegalStateException("SM3Hmac final operation failed");
        }
        return result;
    }

    public byte[] doFinal(byte[] data) {
        update(data);
        return doFinal();
    }

    @Override
    public void close() {
        if (pointer != 0) {
            nativeCrypto().sm3hmacFreeCtx(pointer);
            super.close();
        }
    }

    public void reset() {
        if (pointer == 0
                || nativeCrypto().sm3hmacReset(pointer) != OPENSSL_SUCCESS) {
            throw new IllegalStateException("SM3Hmac reset operation failed");
        }
    }

    @Override
    protected NativeSM3HMac clone() {
        if (pointer == 0) {
            throw new IllegalStateException("Cannot clone closed SM3Hmac instance");
        }

        long clonePointer = nativeCrypto().sm3hmacClone(pointer);
        if (clonePointer == 0) {
            throw new IllegalStateException("SM3Hmac clone operation failed");
        }
        return new NativeSM3HMac(clonePointer);
    }
}
