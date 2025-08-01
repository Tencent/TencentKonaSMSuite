/*
 * Copyright (C) 2022, 2025, Tencent. All rights reserved.
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

import java.security.InvalidKeyException;

public abstract class SymmetricCipher {

    abstract int getBlockSize();

    abstract void init(boolean decrypting, String algorithm, byte[] key,
                       SM4Params paramSpec) throws InvalidKeyException;

    abstract SM4Params getParamSpec();

    abstract byte[] encryptBlock(byte[] plaintext, int offset, int length);

    abstract byte[] encryptBlockFinal(byte[] plaintext, int offset, int length);

    abstract byte[] decryptBlock(byte[] ciphertext, int offset, int length);

    abstract byte[] decryptBlockFinal(byte[] ciphertext, int offset, int length);

    abstract void updateAAD(byte[] aad);
}
