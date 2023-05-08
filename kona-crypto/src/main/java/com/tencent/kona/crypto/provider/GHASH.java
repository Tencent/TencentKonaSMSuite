/*
 * Copyright (c) 2013, 2021, Oracle and/or its affiliates. All rights reserved.
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
/*
 * (C) Copyright IBM Corp. 2013
 * Copyright (c) 2015 Red Hat, Inc.
 */

package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.util.Constants;
import com.tencent.kona.sun.security.action.GetPropertyAction;

import java.nio.ByteBuffer;
import java.security.ProviderException;

import static com.tencent.kona.crypto.CryptoUtils.longToBytes8;

/**
 * This class represents the GHASH function defined in NIST 800-38D
 * under section 6.4. It needs to be constructed w/ a hash subkey, i.e.
 * block H. Given input of 128-bit blocks, it will process and output
 * a 128-bit block.
 *
 * <p>This function is used in the implementation of GCM mode.
 *
 * @since 1.8
 */

final class GHASH implements Cloneable, GCM {

    // preTableSize: ZERO, 32K
    private static final String PRE_TABLE_SIZE
            = GetPropertyAction.privilegedGetProperty(
                    "com.tencent.kona.crypto.gcm.preTableSize", "32K");

    private static long getLong(byte[] buffer, int offset) {
        long result = 0;
        int end = offset + 8;
        for (int i = offset; i < end; ++i) {
            result = (result << 8) + (buffer[i] & 0xFF);
        }
        return result;
    }

    private static void putLong(byte[] buffer, int offset, long value) {
        int end = offset + 8;
        for (int i = end - 1; i >= offset; --i) {
            buffer[i] = (byte) value;
            value >>= 8;
        }
    }

    private static final int SM4_BLOCK_SIZE = Constants.SM4_BLOCK_SIZE;

    // Maximum buffer size rotating ByteBuffer->byte[] intrinsic copy
    private static final int MAX_LEN = 1024;

    /* subkeyHtbl and state are stored in long[] for GHASH intrinsic use */

    // hashtable subkeyHtbl holds 2*9 powers of subkeyH computed using
    // carry-less multiplication
    private long[] subkeyHtbl;

    // buffer for storing hash
    private final long[] state;

    // variables for save/restore calls
    private long stateSave0, stateSave1;

    private final GFMultiplier multiplier;

    /**
     * Initializes the cipher in the specified mode with the given key
     * and iv.
     *
     * @param subkeyH the hash subkey
     *
     * @exception ProviderException if the given key is inappropriate for
     * initializing this digest
     */
    GHASH(byte[] subkeyH) throws ProviderException {
        if ((subkeyH == null) || subkeyH.length != SM4_BLOCK_SIZE) {
            throw new ProviderException("Internal error");
        }
        state = new long[2];
        subkeyHtbl = new long[2*9];
        subkeyHtbl[0] = getLong(subkeyH, 0);
        subkeyHtbl[1] = getLong(subkeyH, 8);

        multiplier = multiplier(subkeyH);
    }

    // Cloning constructor
    private GHASH(GHASH g) {
        state = g.state.clone();
        subkeyHtbl = g.subkeyHtbl.clone();

        byte[] subkeyH = new byte[SM4_BLOCK_SIZE];
        longToBytes8(subkeyHtbl[0], subkeyH, 0);
        longToBytes8(subkeyHtbl[1], subkeyH, 8);
        multiplier = multiplier(subkeyH);
    }

    private GFMultiplier multiplier(byte[] subkeyH) {
        if ("32K".equalsIgnoreCase(PRE_TABLE_SIZE)) {
            return GFMultipliers.gfmWith32KPreTable(subkeyH);
        } else {
            return GFMultipliers.gfmWithoutPreTable(subkeyH);
        }
    }

    @Override
    public GHASH clone() {
        return new GHASH(this);
    }

    /**
     * Resets the GHASH object to its original state, i.e. blank w/
     * the same subkey H. Used after digest() is called and to re-use
     * this object for different data w/ the same H.
     */
    void reset() {
        state[0] = 0;
        state[1] = 0;
    }

    /**
     * Save the current snapshot of this GHASH object.
     */
    void save() {
        stateSave0 = state[0];
        stateSave1 = state[1];
    }

    /**
     * Restores this object using the saved snapshot.
     */
    void restore() {
        state[0] = stateSave0;
        state[1] = stateSave1;
    }

    private void processBlock(byte[] data, int ofs, long[] st) {
        st[0] ^= getLong(data, ofs);
        st[1] ^= getLong(data, ofs + 8);
        multiplier.multiply(st);
    }

    int update(byte[] in) {
        return update(in, 0, in.length);
    }

    int update(byte[] in, int inOfs, int inLen) {
        if (inLen == 0) {
            return 0;
        }
        int len = inLen - (inLen % SM4_BLOCK_SIZE);
        ghashRangeCheck(in, inOfs, len, state, subkeyHtbl);
        processBlocks(in, inOfs, len / SM4_BLOCK_SIZE, state);
        return len;
    }

    // Will process as many blocks it can and will leave the remaining.
    int update(ByteBuffer ct, int inLen) {
        inLen -= (inLen % SM4_BLOCK_SIZE);
        if (inLen == 0) {
            return 0;
        }

        // If ct is a direct bytebuffer, send it directly to the intrinsic
        if (ct.isDirect()) {
            int processed = inLen;
            processBlocksDirect(ct, inLen);
            return processed;
        } else if (!ct.isReadOnly()) {
            // If a non-read only heap bytebuffer, use the array update method
            int processed = update(ct.array(),
                ct.arrayOffset() + ct.position(),
                inLen);
            ct.position(ct.position() + processed);
            return processed;
        }

        // Read only heap bytebuffers have to be copied and operated on
        int to_process = inLen;
        byte[] in = new byte[Math.min(MAX_LEN, inLen)];
        while (to_process > MAX_LEN ) {
            ct.get(in, 0, MAX_LEN);
            update(in, 0 , MAX_LEN);
            to_process -= MAX_LEN;
        }
        ct.get(in, 0, to_process);
        update(in, 0, to_process);
        return inLen;
    }

    int doFinal(ByteBuffer src, int inLen) {
        int processed = 0;

        if (inLen >= SM4_BLOCK_SIZE) {
            processed = update(src, inLen);
        }

        if (inLen == processed) {
            return processed;
        }
        byte[] block = new byte[SM4_BLOCK_SIZE];
        src.get(block, 0, inLen - processed);
        update(block, 0, SM4_BLOCK_SIZE);
        return inLen;
    }

    int doFinal(byte[] in, int inOfs, int inLen) {
        int remainder = inLen % SM4_BLOCK_SIZE;
        inOfs += update(in, inOfs, inLen - remainder);
        if (remainder > 0) {
            byte[] block = new byte[SM4_BLOCK_SIZE];
            System.arraycopy(in, inOfs, block, 0,
                remainder);
            update(block, 0, SM4_BLOCK_SIZE);
        }
        return inLen;
    }

    private static void ghashRangeCheck(byte[] in, int inOfs, int inLen,
        long[] st, long[] subH) {
        if (inLen < 0) {
            throw new RuntimeException("invalid input length: " + inLen);
        }
        if (inOfs < 0) {
            throw new RuntimeException("invalid offset: " + inOfs);
        }
        if (inLen > in.length - inOfs) {
            throw new RuntimeException("input length out of bound: " +
                                       inLen + " > " + (in.length - inOfs));
        }
        if (inLen % SM4_BLOCK_SIZE != 0) {
            throw new RuntimeException("input length/block size mismatch: " +
                                       inLen);
        }

        // These two checks are for C2 checking
        if (st.length != 2) {
            throw new RuntimeException("internal state has invalid length: " +
                                       st.length);
        }
        if (subH.length != 18) {
            throw new RuntimeException("internal subkeyHtbl has invalid length: " +
                                       subH.length);
        }
    }
    /*
     * This is an intrinsified method.  The method's argument list must match
     * the hotspot signature.  This method and methods called by it, cannot
     * throw exceptions or allocate arrays as it will breaking intrinsics
     */
    private void processBlocks(byte[] data, int inOfs, int blocks, long[] st) {
        int offset = inOfs;
        while (blocks > 0) {
            processBlock(data, offset, st);
            blocks--;
            offset += SM4_BLOCK_SIZE;
        }
    }

    // ProcessBlock for Direct ByteBuffers
    private void processBlocksDirect(ByteBuffer ct, int inLen) {
        byte[] data = new byte[Math.min(MAX_LEN, inLen)];
        while (inLen > MAX_LEN) {
            ct.get(data, 0, MAX_LEN);
            processBlocks(data, 0, MAX_LEN / SM4_BLOCK_SIZE, state);
            inLen -= MAX_LEN;
        }
        if (inLen >= SM4_BLOCK_SIZE) {
            int len = inLen - (inLen % SM4_BLOCK_SIZE);
            ct.get(data, 0, len);
            processBlocks(data, 0, len / SM4_BLOCK_SIZE, state);
        }
    }

    byte[] digest() {
        byte[] result = new byte[SM4_BLOCK_SIZE];
        putLong(result, 0, state[0]);
        putLong(result, 8, state[1]);
        reset();
        return result;
    }


    /**
     * None of the out or dst values are necessary, they are to satisfy the
     * GCM interface requirement
     */
    @Override
    public int update(byte[] in, int inOfs, int inLen, byte[] out, int outOfs) {
        return update(in, inOfs, inLen);
    }

    @Override
    public int update(byte[] in, int inOfs, int inLen, ByteBuffer dst) {
        return update(in, inOfs, inLen);
    }

    @Override
    public int update(ByteBuffer src, ByteBuffer dst) {
        return update(src, src.remaining());
    }

    @Override
    public int doFinal(byte[] in, int inOfs, int inLen, byte[] out,
        int outOfs) {
        return doFinal(in, inOfs, inLen);
    }

    @Override
    public int doFinal(ByteBuffer src, ByteBuffer dst) {
        return doFinal(src, src.remaining());
    }
}
