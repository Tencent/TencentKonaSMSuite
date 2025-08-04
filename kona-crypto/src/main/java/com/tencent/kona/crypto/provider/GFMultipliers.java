/*
 * Copyright (C) 2022, 2023, Tencent. All rights reserved.
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

package com.tencent.kona.crypto.provider;

import static com.tencent.kona.crypto.CryptoUtils.longToBytes8;

/**
 * Some implementations on the multiplications over GF(2 ^ 128).
 *
 * Refer to The Galois/Counter Mode of Operation (GCM) [GCMO]
 * https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
 */
class GFMultipliers {

    // [GCMO] section 2.5, R = 1110 0001 0000 .... 0000
    private static final long R = 0xE100000000000000L;

    static GFMultiplier gfmWithoutPreTable(byte[] subkeyH) {
        return new GFMWithoutPreTable(subkeyH);
    }

    static GFMultiplier gfmWith32KPreTable(byte[] subkeyH) {
        return new GFMWith32KTable(subkeyH);
    }

    // Without precomputed table
    private static final class GFMWithoutPreTable extends GFMultiplier {

        private GFMWithoutPreTable(byte[] subkeyH) {
            super(subkeyH);
        }

        @Override
        public void multiply(long[] block) {
            long Z0 = 0;
            long Z1 = 0;
            long V0 = subkeyWords[0];
            long V1 = subkeyWords[1];
            long X;

            // Separate loops for processing state[0] and state[1].
            X = block[0];
            for (int i = 0; i < 64; i++) {
                // Zi+1 = Zi if bit i of x is 0
                long mask = X >> 63;
                Z0 ^= V0 & mask;
                Z1 ^= V1 & mask;

                // Save mask for conditional reduction below.
                mask = (V1 << 63) >> 63;

                // V = rightshift(V)
                long carry = V0 & 1;
                V0 = V0 >>> 1;
                V1 = (V1 >>> 1) | (carry << 63);

                // Conditional reduction modulo P128.
                V0 ^= R & mask;
                X <<= 1;
            }

            X = block[1];
            for (int i = 64; i < 127; i++) {
                // Zi+1 = Zi if bit i of x is 0
                long mask = X >> 63;
                Z0 ^= V0 & mask;
                Z1 ^= V1 & mask;

                // Save mask for conditional reduction below.
                mask = (V1 << 63) >> 63;

                // V = rightshift(V)
                long carry = V0 & 1;
                V0 = V0 >>> 1;
                V1 = (V1 >>> 1) | (carry << 63);

                // Conditional reduction.
                V0 ^= R & mask;
                X <<= 1;
            }

            // calculate Z128
            long mask = X >> 63;
            Z0 ^= V0 & mask;
            Z1 ^= V1 & mask;

            // Save result.
            block[0] = Z0;
            block[1] = Z1;
        }
    }

    // With a precomputed table,
    // which consumes 256 * 2 * 64 = 32768 or 32K bits
    private static final class GFMWith32KTable extends GFMultiplier {

        private final long[][] table = preTable();

        GFMWith32KTable(byte[] subkeyH) {
            super(subkeyH);
        }

        private long[][] preTable() {
            long[][] table = new long[256][2];

            table[1][0] = subkeyWords[0];
            table[1][1] = subkeyWords[1];
            multiplyP7(table[1]);

            for (int i = 2; i < 256; i += 2) {
                divideP(table[i >> 1], table[i]);
                add(table[i], table[1], table[i + 1]);
            }

            return table;
        }

        private static void multiplyP7(long[] x) {
            long x0 = x[0];
            long x1 = x[1];

            long c = x1 << 57;
            x[0] = (x0 >>> 7) ^ c ^ (c >>> 1) ^ (c >>> 2) ^ (c >>> 7);
            x[1] = (x1 >>> 7) | (x0 << 57);
        }

        private static void divideP(long[] x, long[] z) {
            long x0 = x[0];
            long x1 = x[1];

            long m = x0 >> 63;
            x0 ^= m & R;
            z[0] = (x0 << 1) | (x1 >>> 63);
            z[1] = (x1 << 1) | -m;
        }

        private static void add(long[] x, long[] y, long[] z) {
            z[0] = x[0] ^ y[0];
            z[1] = x[1] ^ y[1];
        }

        public void multiply(long[] block) {
            byte[] buf = new byte[16];
            longToBytes8(block[0], buf, 0);
            longToBytes8(block[1], buf, 8);

            long[] t = table[buf[15] & 0xFF];
            long z0 = t[0];
            long z1 = t[1];

            for (int i = 14; i >= 0; i--) {
                t = table[buf[i] & 0xFF];

                long c = z1 << 56;
                z1 = t[1] ^ ((z1 >>> 8) | (z0 << 56));
                z0 = t[0] ^ (z0 >>> 8) ^ c ^ (c >>> 1) ^ (c >>> 2) ^ (c >>> 7);
            }

            block[0] = z0;
            block[1] = z1;
        }
    }
}
