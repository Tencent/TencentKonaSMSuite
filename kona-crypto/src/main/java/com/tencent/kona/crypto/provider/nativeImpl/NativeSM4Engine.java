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

import com.tencent.kona.crypto.util.Sweeper;

/**
 * Native SM4 engine.
 * Note this engine just be for testing purpose.
 */
public final class NativeSM4Engine {

    private static final Sweeper SWEEPER = Sweeper.instance();

    private final NativeSM4.SM4ECB sm4;

    public NativeSM4Engine(byte[] key, boolean encrypt) {
        sm4 = new NativeSM4.SM4ECB(encrypt, false, key);
        SWEEPER.register(this, new SweepNativeRef(sm4));
    }

    public void processBlock(
            byte[] in, int inOffset,
            byte[] out, int outOffset) {
        sm4.processBlock(in, inOffset, out, outOffset);
    }
}
