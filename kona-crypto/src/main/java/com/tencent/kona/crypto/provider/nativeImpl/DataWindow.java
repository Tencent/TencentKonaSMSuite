/*
 * Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
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

import com.tencent.kona.crypto.CryptoUtils;

import java.util.Arrays;

/**
 * A data windows with fixed n-bytes size.
 * It holds the last (at most) n-bytes data.
 */
class DataWindow {

    private byte[] window;

    private int offset = 0;

    DataWindow(int size) {
        if (size < 0) {
            throw new IllegalArgumentException("Size must not be negative");
        }

        window = new byte[size];
    }

    /**
     * Put new data to the window.
     * If the space is not enough, some or all old bytes will be evicted
     * from the window.
     */
    byte[] put(byte[] src, int srcOffset, int srcLen) {
        checkRange(src, srcOffset, srcLen);

        // The excluded data, including the evicted data and the
        byte[] excluded = new byte[0];

        if (space() >= srcLen) { // The space is enough
            System.arraycopy(src, srcOffset, window, offset, srcLen);
            offset += srcLen;
        } else { // The space is not enough
            int size = dataSize();
            int totalSize = size + srcLen;
            int excludedSize = totalSize - windowSize();
            int evictedSize = Math.min(excludedSize, size);

            excluded = new byte[excludedSize];
            System.arraycopy(window, 0, excluded, 0, evictedSize);
            if (evictedSize < excludedSize) {
                System.arraycopy(src, srcOffset, excluded, evictedSize, excludedSize - evictedSize);
            }

            byte[] tempWindow = new byte[windowSize()];
            System.arraycopy(window, evictedSize, tempWindow, 0, size - evictedSize);
            // TODO Copy the data to the excluded array may consume much performance.
            int srcLastPartSize = windowSize() - size + evictedSize;
            System.arraycopy(
                    src, srcOffset + srcLen - srcLastPartSize,
                    tempWindow, size - evictedSize,
                    srcLastPartSize);

            offset = windowSize();
            window = tempWindow;
        }

        return excluded;
    }

    byte[] put(byte[] src) {
        return put(src, 0, src.length);
    }

    private void checkRange(byte[] src, int srcOffset, int srcLen) {
        if (src.length < srcOffset + srcLen) {
            throw new ArrayIndexOutOfBoundsException(
                    "src.length < srcOffset + srcLength");
        }
    }

    byte[] data() {
        return CryptoUtils.copy(window, 0, dataSize());
    }

    int space() {
        return windowSize() - dataSize();
    }

    boolean moreSpace() {
        return space() > 0;
    }

    /**
     * The size of the data.
     */
    int dataSize() {
        return offset;
    }

    /**
     * The fixed size of the window.
     */
    int windowSize() {
        return window.length;
    }

    void reset() {
        Arrays.fill(window, (byte) 0);
        offset = 0;
    }
}
