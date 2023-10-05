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

package com.tencent.kona.sun.security.ssl;

import com.tencent.kona.crypto.CryptoInsts;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.tencent.kona.sun.security.ssl.HandshakeHash.CloneableHash;
import com.tencent.kona.sun.security.ssl.HandshakeHash.NonCloneableHash;
import com.tencent.kona.sun.security.ssl.HandshakeHash.TranscriptHash;

final class TLCPHandshakeHash implements TranscriptHash {

    private final TranscriptHash transcriptHash;
    private final ByteArrayOutputStream baos;

    TLCPHandshakeHash() {
        MessageDigest md = null;
        try {
            md = CryptoInsts.getMessageDigest("SM3");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SM3 is not supported", e);
        }

        if (md instanceof Cloneable) {
            transcriptHash = new CloneableHash(md);
            this.baos = new ByteArrayOutputStream();
        } else {
            transcriptHash = new NonCloneableHash(md);
            this.baos = null;
        }
    }

    @Override
    public void update(byte[] input, int offset, int length) {
        transcriptHash.update(input, offset, length);
        if (baos != null) {
            baos.write(input, offset, length);
        }
    }

    @Override
    public byte[] digest() {
        return transcriptHash.digest();
    }

    @Override
    public byte[] archived() {
        if (baos != null) {
            return baos.toByteArray();
        } else {
            return transcriptHash.archived();
        }
    }
}
