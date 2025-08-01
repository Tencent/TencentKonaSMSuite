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

import java.util.Objects;

import static com.tencent.kona.crypto.provider.nativeImpl.NativeCrypto.*;

/**
 * The SM3 native implementation.
 */
final class NativeSM3 extends NativeRef implements Cloneable {

    public NativeSM3() {
        super(nativeCrypto().sm3CreateCtx());
    }

    public NativeSM3(long pointer) {
        super(pointer);
    }

    public void update(byte[] data) {
        Objects.requireNonNull(data);

        if (pointer == 0 || nativeCrypto().sm3Update(pointer, data) != OPENSSL_SUCCESS) {
            throw new IllegalStateException("sm3 update operation failed");
        }
    }

    public byte[] doFinal() {
        byte[] result = pointer == 0
                ? null
                : nativeCrypto().sm3Final(pointer);
        if (result == null) {
            throw new IllegalStateException("sm3 final operation failed");
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
            nativeCrypto().sm3FreeCtx(pointer);
            super.close();
        }
    }

    public void reset() {
        if (pointer == 0 || nativeCrypto().sm3Reset(pointer) != OPENSSL_SUCCESS) {
            throw new IllegalStateException("sm3 reset operation failed");
        }
    }

    @Override
    protected NativeSM3 clone() {
        if (pointer == 0) {
            throw new IllegalStateException("Cannot clone SM3 instance");
        }

        long clonePointer = nativeCrypto().sm3Clone(pointer);
        if (clonePointer <= 0) {
            throw new IllegalStateException("SM3 clone operation failed");
        }
        return new NativeSM3(clonePointer);
    }
}
