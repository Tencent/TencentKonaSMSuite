/*
 * Copyright (c) 2003, 2022, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.tencent.kona.com.sun.crypto.provider;

import java.security.MessageDigest;
import java.util.Arrays;

public class PKCS12PBECipherCoreUtil {

    static final int MAC_KEY = 3;

    // Uses supplied hash algorithm
    static byte[] derive(char[] chars, byte[] salt, int ic, int n, int type,
        String hashAlgo, int blockLength) {

        // Add in trailing NULL terminator.  Special case:
        // no terminator if password is "\0".
        int length = chars.length*2;
        if (length == 2 && chars[0] == 0) {
            chars = new char[0];
            length = 0;
        } else {
            length += 2;
        }

        byte[] passwd = new byte[length];
        for (int i = 0, j = 0; i < chars.length; i++, j+=2) {
            passwd[j] = (byte) ((chars[i] >>> 8) & 0xFF);
            passwd[j+1] = (byte) (chars[i] & 0xFF);
        }
        byte[] key = new byte[n];

        try {
            MessageDigest sha = MessageDigest.getInstance(hashAlgo);

            int v = blockLength;
            int u = sha.getDigestLength();
            int c = roundup(n, u) / u;
            byte[] D = new byte[v];
            int s = roundup(salt.length, v);
            int p = roundup(passwd.length, v);
            byte[] I = new byte[s + p];

            Arrays.fill(D, (byte)type);
            concat(salt, I, 0, s);
            concat(passwd, I, s, p);
            Arrays.fill(passwd, (byte) 0x00);

            byte[] Ai;
            byte[] B = new byte[v];

            int i = 0;
            for (; ; i++, n -= u) {
                sha.update(D);
                sha.update(I);
                Ai = sha.digest();
                for (int r = 1; r < ic; r++)
                    Ai = sha.digest(Ai);
                System.arraycopy(Ai, 0, key, u * i, Math.min(n, u));
                if (i + 1 == c) {
                    break;
                }
                concat(Ai, B, 0, v);
                addOne(v, B);   // add 1 into B

                for (int j = 0; j < I.length; j += v) {
                    addTwo(v, B, I, j); // add B into I from j
                }
            }
            Arrays.fill(I, (byte)0);
        } catch (Exception e) {
            throw new RuntimeException("internal error: " + e);
        }
        return key;
    }

    // Add 1 to b (as integer)
    private static void addOne(int len, byte[] b) {
        for (int i = len - 1; i >= 0; i--) {
            if ((b[i] & 0xff) != 255) {
                b[i]++;
                break;
            } else {
                b[i] = 0;
            }
        }
    }

    // Add src (as integer) to dst from offset (as integer)
    private static void addTwo(int len, byte[] src, byte[] dst, int offset) {
        int carry = 0;
        for (int i = len - 1; i >= 0; i--) {
            int sum = (src[i] & 0xff) + (dst[i + offset] & 0xff) + carry;
            carry = sum >> 8;
            dst[i + offset] = (byte)sum;
        }
    }

    private static int roundup(int x, int y) {
        return ((x + (y - 1)) / y) * y;
    }

    private static void concat(byte[] src, byte[] dst, int start, int len) {
        if (src.length == 0) {
            return;
        }
        int loop = len / src.length;
        int off, i;
        for (i = 0, off = 0; i < loop; i++, off += src.length)
            System.arraycopy(src, 0, dst, off + start, src.length);
        System.arraycopy(src, 0, dst, off + start, len - off);
    }
}
