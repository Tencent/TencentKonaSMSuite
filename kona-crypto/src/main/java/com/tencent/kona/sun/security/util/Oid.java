/*
 * Copyright (C) 2021, 2022, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. THL A29 Limited designates
 * this particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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

package com.tencent.kona.sun.security.util;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * In JDK 17, the constructor ObjectIdentifier(String oid) is restricted as
 * private scope. This class Oid just be used to work around this trouble.
 *
 * This provider has to use this utility to create ObjectIdentifier instance.
 */
public class Oid {

    /*
     * The maximum encoded OID length, excluding the ASN.1 encoding tag and
     * length.
     *
     * In theory, there is no maximum size for OIDs.  However, there are some
     * limitation in practice.
     *
     * RFC 5280 mandates support for OIDs that have arc elements with values
     * that are less than 2^28 (that is, they MUST be between 0 and
     * 268,435,455, inclusive), and implementations MUST be able to handle
     * OIDs with up to 20 elements (inclusive).  Per RFC 5280, an encoded
     * OID should be less than 80 bytes for safe interoperability.
     *
     * This class could be used for protocols other than X.509 certificates.
     * To be safe, a relatively large but still reasonable value is chosen
     * as the restriction in JDK.
     */
    private static final int MAXIMUM_OID_SIZE = 4096;    // 2^12

    public static ObjectIdentifier of(String oid) {
        try {
            return of(encode(oid));
        } catch (IOException e) {
            throw new RuntimeException("OID is wrong: " + oid);
        }
    }

    public static ObjectIdentifier of(int[] values) {
        try {
            checkCount(values.length);
            checkFirstComponent(values[0]);
            checkSecondComponent(values[0], values[1]);
            for (int i = 2; i < values.length; i++)
                checkOtherComponent(i, values[i]);
            return of(init(values, values.length));
        } catch (IOException e) {
            throw new RuntimeException("OID is wrong: "
                    + Arrays.toString(values));
        }
    }

    public static ObjectIdentifier of(byte[] encoded) throws IOException {
        DerOutputStream derOut = new DerOutputStream();
        derOut.write(DerValue.tag_ObjectId, encoded);
        return new ObjectIdentifier(new DerInputStream(derOut.toByteArray()));
    }

    public static ObjectIdentifier of(KnownOIDs oid) {
        return of(oid.value());
    }

    private static byte[] init(int[] components, int length) throws IOException {
        int pos = 0;
        byte[] tmp = new byte[length * 5 + 1];  // +1 for empty input

        if (components[1] < Integer.MAX_VALUE - components[0] * 40) {
            pos += pack7Oid(components[0] * 40 + components[1], tmp, pos);
        } else {
            BigInteger big = BigInteger.valueOf(components[1]);
            big = big.add(BigInteger.valueOf(components[0] * 40L));
            pos += pack7Oid(big, tmp, pos);
        }

        for (int i = 2; i < length; i++) {
            pos += pack7Oid(components[i], tmp, pos);

            checkOidSize(pos);
        }

        byte[] encoding = new byte[pos];
        System.arraycopy(tmp, 0, encoding, 0, pos);
        return encoding;
    }

    private static byte[] encode(String oid) throws IOException {
        int ch = '.';
        int start = 0;
        int end;

        int pos = 0;
        byte[] tmp = new byte[oid.length()];
        int first = 0;
        int count = 0;

        try {
            String comp;
            do {
                int length; // length of one section
                end = oid.indexOf(ch,start);
                if (end == -1) {
                    comp = oid.substring(start);
                    length = oid.length() - start;
                } else {
                    comp = oid.substring(start,end);
                    length = end - start;
                }

                if (length > 9) {
                    BigInteger bignum = new BigInteger(comp);
                    if (count == 0) {
                        checkFirstComponent(bignum);
                        first = bignum.intValue();
                    } else {
                        if (count == 1) {
                            checkSecondComponent(first, bignum);
                            bignum = bignum.add(BigInteger.valueOf(40L * first));
                        } else {
                            checkOtherComponent(count, bignum);
                        }
                        pos += pack7Oid(bignum, tmp, pos);
                    }
                } else {
                    int num = Integer.parseInt(comp);
                    if (count == 0) {
                        checkFirstComponent(num);
                        first = num;
                    } else {
                        if (count == 1) {
                            checkSecondComponent(first, num);
                            num += 40 * first;
                        } else {
                            checkOtherComponent(count, num);
                        }
                        pos += pack7Oid(num, tmp, pos);
                    }
                }
                start = end + 1;
                count++;

                checkOidSize(pos);
            } while (end != -1);

            checkCount(count);
            byte[] encoding = new byte[pos];
            System.arraycopy(tmp, 0, encoding, 0, pos);
            return encoding;
        } catch (IOException ioe) { // already detected by checkXXX
            throw ioe;
        } catch (Exception e) {
            throw new IOException("ObjectIdentifier() -- Invalid format: "
                    + e, e);
        }
    }

    /**
     * Repack all bits from input to output. On the both sides, only a portion
     * (from the least significant bit) of the 8 bits in a byte is used. This
     * number is defined as the number of useful bits (NUB) for the array. All
     * used bits from the input byte array and repacked into the output in the
     * exactly same order. The output bits are aligned so that the final bit of
     * the input (the least significant bit in the last byte), when repacked as
     * the final bit of the output, is still at the least significant position.
     * Zeroes will be padded on the left side of the first output byte if
     * necessary. All unused bits in the output are also zeroed.
     *
     * For example: if the input is 01001100 with NUB 8, the output which
     * has a NUB 6 will look like:
     *      00000001 00001100
     * The first 2 bits of the output bytes are unused bits. The other bits
     * turn out to be 000001 001100. While the 8 bits on the right are from
     * the input, the left 4 zeroes are padded to fill the 6 bits space.
     *
     * @param in        the input byte array
     * @param ioffset   start point inside <code>in</code>
     * @param ilength   number of bytes to repack
     * @param iw        NUB for input
     * @param ow        NUB for output
     * @return          the repacked bytes
     */
    private static byte[] pack(byte[] in,
                               int ioffset, int ilength, int iw, int ow) {
        assert (iw > 0 && iw <= 8): "input NUB must be between 1 and 8";
        assert (ow > 0 && ow <= 8): "output NUB must be between 1 and 8";

        if (iw == ow) {
            return in.clone();
        }

        int bits = ilength * iw;    // number of all used bits
        byte[] out = new byte[(bits+ow-1)/ow];

        // starting from the 0th bit in the input
        int ipos = 0;

        // the number of padding 0's needed in the output, skip them
        int opos = (bits+ow-1)/ow*ow-bits;

        while(ipos < bits) {
            int count = iw - ipos%iw;   // unpacked bits in current input byte
            if (count > ow - opos%ow) { // free space available in output byte
                count = ow - opos%ow;   // choose the smaller number
            }

            // and move them!
            out[opos/ow] |=                     // paste!
                    (((in[ioffset+ipos/iw]+256)     // locate the byte (+256 so that it's never negative)
                            >> (iw-ipos%iw-count)) &    // move to the end of a byte
                            ((1 << (count))-1))           // zero out all other bits
                            << (ow-opos%ow-count);  // move to the output position
            ipos += count;  // advance
            opos += count;  // advance
        }
        return out;
    }

    /**
     * Repack from NUB 8 to a NUB 7 OID sub-identifier, remove all
     * unnecessary 0 headings, set the first bit of all non-tail
     * output bytes to 1 (as ITU-T Rec. X.690 8.19.2 says), and
     * paste it into an existing byte array.
     * @param out the existing array to be pasted into
     * @param ooffset the starting position to paste
     * @return the number of bytes pasted
     */
    private static int pack7Oid(byte[] in,
            int ioffset, int ilength, byte[] out, int ooffset) {
        byte[] pack = pack(in, ioffset, ilength, 8, 7);
        int firstNonZero = pack.length-1;   // paste at least one byte
        for (int i=pack.length-2; i>=0; i--) {
            if (pack[i] != 0) {
                firstNonZero = i;
            }
            pack[i] |= 0x80;
        }
        System.arraycopy(pack, firstNonZero,
                out, ooffset, pack.length-firstNonZero);
        return pack.length-firstNonZero;
    }

    /**
     * Repack from NUB 7 to NUB 8, remove all unnecessary 0
     * headings, and paste it into an existing byte array.
     * @param out the existing array to be pasted into
     * @param ooffset the starting position to paste
     * @return the number of bytes pasted
     */
    private static int pack8(byte[] in,
                             int ioffset, int ilength, byte[] out, int ooffset) {
        byte[] pack = pack(in, ioffset, ilength, 7, 8);
        int firstNonZero = pack.length-1;   // paste at least one byte
        for (int i=pack.length-2; i>=0; i--) {
            if (pack[i] != 0) {
                firstNonZero = i;
            }
        }
        System.arraycopy(pack, firstNonZero,
                out, ooffset, pack.length-firstNonZero);
        return pack.length-firstNonZero;
    }

    /**
     * Pack the int into a OID sub-identifier DER encoding
     */
    private static int pack7Oid(int input, byte[] out, int ooffset) {
        byte[] b = new byte[4];
        b[0] = (byte)(input >> 24);
        b[1] = (byte)(input >> 16);
        b[2] = (byte)(input >> 8);
        b[3] = (byte)(input);
        return pack7Oid(b, 0, 4, out, ooffset);
    }

    /**
     * Pack the BigInteger into a OID subidentifier DER encoding
     */
    private static int pack7Oid(BigInteger input, byte[] out, int ooffset) {
        byte[] b = input.toByteArray();
        return pack7Oid(b, 0, b.length, out, ooffset);
    }

    /**
     * Private methods to check validity of OID. They must be --
     * 1. at least 2 components
     * 2. all components must be non-negative
     * 3. the first must be 0, 1 or 2
     * 4. if the first is 0 or 1, the second must be <40
     */

    /**
     * Check the DER encoding. Since DER encoding defines that the integer bits
     * are unsigned, so there's no need to check the MSB.
     */
    private static void check(byte[] encoding) throws IOException {
        int length = encoding.length;
        if (length < 1 ||      // too short
                (encoding[length - 1] & 0x80) != 0) {  // not ended
            throw new IOException("ObjectIdentifier() -- " +
                    "Invalid DER encoding, not ended");
        }
        for (int i=0; i<length; i++) {
            // 0x80 at the beginning of a subidentifier
            if (encoding[i] == (byte)0x80 &&
                    (i==0 || (encoding[i-1] & 0x80) == 0)) {
                throw new IOException("ObjectIdentifier() -- " +
                        "Invalid DER encoding, useless extra octet detected");
            }
        }
    }

    private static void checkCount(int count) throws IOException {
        if (count < 2) {
            throw new IOException("ObjectIdentifier() -- " +
                    "Must be at least two oid components ");
        }
    }

    private static void checkFirstComponent(int first) throws IOException {
        if (first < 0 || first > 2) {
            throw new IOException("ObjectIdentifier() -- " +
                    "First oid component is invalid ");
        }
    }

    private static void checkFirstComponent(
            BigInteger first) throws IOException {
        if (first.signum() == -1
                || first.compareTo(BigInteger.valueOf(2)) > 0) {
            throw new IOException("ObjectIdentifier() -- " +
                    "First oid component is invalid ");
        }
    }

    private static void checkSecondComponent(
            int first, int second) throws IOException {
        if (second < 0 || first != 2 && second > 39) {
            throw new IOException("ObjectIdentifier() -- " +
                    "Second oid component is invalid ");
        }
    }

    private static void checkSecondComponent(
            int first, BigInteger second) throws IOException {
        if (second.signum() == -1 ||
                first != 2 &&
                        second.compareTo(BigInteger.valueOf(39)) == 1) {
            throw new IOException("ObjectIdentifier() -- " +
                    "Second oid component is invalid ");
        }
    }

    private static void checkOtherComponent(int i, int num) throws IOException {
        if (num < 0) {
            throw new IOException("ObjectIdentifier() -- " +
                    "oid component #" + (i+1) + " must be non-negative ");
        }
    }

    private static void checkOtherComponent(
            int i, BigInteger num) throws IOException {
        if (num.signum() == -1) {
            throw new IOException("ObjectIdentifier() -- " +
                    "oid component #" + (i+1) + " must be non-negative ");
        }
    }

    private static void checkOidSize(int oidLength) throws IOException {
        if (oidLength < 0) {
            throw new IOException("ObjectIdentifier encoded length was " +
                    "negative: " + oidLength);
        }

        if (oidLength > MAXIMUM_OID_SIZE) {
            throw new IOException(
                    "ObjectIdentifier encoded length exceeds " +
                            "the restriction in JDK (OId length(>=): " + oidLength +
                            ", Restriction: " + MAXIMUM_OID_SIZE + ")");
        }
    }
}
