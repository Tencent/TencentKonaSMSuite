/*
 * Copyright (C) 2022, 2024, Tencent. All rights reserved.
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

import java.util.Arrays;

/**
 * A simplified clone for ByteArrayOutputStream, however the methods
 * are not synchronized. Especially, clear() method resets not only the size,
 * but also the values in the buffer due to security concern.
 */
public class ByteArrayWriter {

    static final int MAX_ARRAY_SIZE = Integer.MAX_VALUE - 8;

    private byte[] buf;
    private int size;

    public ByteArrayWriter(int size) {
        if (size < 0) {
            throw new IllegalArgumentException("Negative initial size: " + size);
        }

        buf = new byte[size];
    }

    public ByteArrayWriter() {
        this(128);
    }

    public ByteArrayWriter(byte[] initData) {
        if (initData == null || initData.length == 0) {
            throw new IllegalArgumentException("Null or empty byte array");
        }

        buf = initData.clone();
        size = initData.length;
    }

    public void write(int b) {
        ensureCapacity(size + 1);
        buf[size] = (byte) b;
        size += 1;
    }

    public void write(byte[] src) {
        write(src, 0, src.length);
    }

    public void write(byte[] src, int off, int len) {
        if (off < 0 || off > src.length || len < 0 ||
                (off + len) - src.length > 0) {
            throw new IndexOutOfBoundsException();
        }

        ensureCapacity(size + len);
        System.arraycopy(src, off, buf, size, len);
        size += len;
    }

    private void ensureCapacity(int minCapacity) {
        // overflow-conscious code
        if (minCapacity - buf.length > 0) {
            grow(minCapacity);
        }
    }

    private void grow(int minCapacity) {
        // overflow-conscious code
        int oldCapacity = buf.length;
        int newCapacity = oldCapacity << 1;
        if (newCapacity - minCapacity < 0) {
            newCapacity = minCapacity;
        }
        if (newCapacity - MAX_ARRAY_SIZE > 0) {
            newCapacity = hugeCapacity(minCapacity);
        }
        buf = Arrays.copyOf(buf, newCapacity);
    }

    private static int hugeCapacity(int minCapacity) {
        if (minCapacity < 0) { // overflow
            throw new OutOfMemoryError();
        }

        return minCapacity > MAX_ARRAY_SIZE ? Integer.MAX_VALUE : MAX_ARRAY_SIZE;
    }

    public void reset() {
        Arrays.fill(buf, (byte) 0x00);
        size = 0;
    }

    public byte[] toByteArray() {
        return Arrays.copyOf(buf, size);
    }

    public int size() {
        return size;
    }

    byte[] buf() {
        return Arrays.copyOf(buf, buf.length);
    }

    int capacity() {
        return buf.length;
    }
}
