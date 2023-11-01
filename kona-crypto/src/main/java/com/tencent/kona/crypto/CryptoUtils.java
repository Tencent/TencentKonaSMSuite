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

package com.tencent.kona.crypto;

import java.math.BigInteger;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.spec.ECPoint;

import com.tencent.kona.crypto.util.RangeUtil;
import com.tencent.kona.java.util.HexFormat;
import com.tencent.kona.crypto.util.Constants;
import com.tencent.kona.sun.security.util.ArrayUtil;

public final class CryptoUtils {

    public static String privilegedGetProperty(String key, String def) {
        return AccessController.doPrivileged(
                (PrivilegedAction<String>) () -> System.getProperty(key, def));
    }

    public static String privilegedGetProperty(String key) {
        return privilegedGetProperty(key, null);
    }

    public static Boolean privilegedGetBoolProperty(String key, String def) {
        return AccessController.doPrivileged(
                (PrivilegedAction<Boolean>) () -> Boolean.parseBoolean(
                        System.getProperty(key, def)));
    }

    public static Boolean privilegedGetBoolProperty(String key) {
        return privilegedGetBoolProperty(key, "false");
    }

    public static boolean isJdk8() {
        return Constants.JDK_VERSION.equals("1.8");
    }

    public static boolean isJdk11() {
        return Constants.JDK_VERSION.equals("11");
    }

    public static boolean isJdk17() {
        return Constants.JDK_VERSION.equals("17");
    }

    public static boolean isAndroid() {
        return Constants.JDK_VENDOR.contains("Android");
    }

    private static final HexFormat HEX = HexFormat.of();

    public static String toHex(byte[] bytes) {
        return HEX.formatHex(bytes);
    }

    public static byte[] toBytes(String hex) {
        return HEX.parseHex(hex);
    }

    // little-endian byte array
    public static byte[] toBytesLE(String hex) {
        byte[] byteArr = toBytes(hex);
        ArrayUtil.reverse(byteArr);
        return byteArr;
    }

    public static BigInteger toBigInt(byte[] value, int offset, int length) {
        byte[] valueCopy = copy(value, offset, length);
        return new BigInteger(1, valueCopy);
    }

    public static BigInteger toBigInt(byte[] value) {
        return toBigInt(value, 0, value.length);
    }

    public static BigInteger toBigInt(String hexValue) {
        return toBigInt(toBytes(hexValue));
    }

    public static int circularLeftShift(int n, int bits) {
        return (n << bits) | (n >>> (32 - bits));
    }

    // BigInteger to little-endian byte array
    public static byte[] toByteArrayLE(BigInteger value) {
        byte[] byteArr = value.toByteArray();
        ArrayUtil.reverse(byteArr);
        return byteArr;
    }

    // Convert 4-bytes in big-endian to integer
    public static int bytes4ToInt(byte[] bytes4, int offset) {
        return ( bytes4[  offset]         << 24)
             | ((bytes4[++offset] & 0xFF) << 16)
             | ((bytes4[++offset] & 0xFF) << 8)
             |  (bytes4[++offset] & 0xFF);
    }

    public static int bytes4ToInt(byte[] bytes4) {
        return bytes4ToInt(bytes4, 0);
    }

    // Convert integer to 4-bytes in big-endian
    public static void intToBytes4(int n, byte[] dest, int offset) {
        dest[  offset] = (byte)(n >>> 24);
        dest[++offset] = (byte)(n >>> 16);
        dest[++offset] = (byte)(n >>> 8);
        dest[++offset] = (byte) n;
    }

    public static void intToBytes4(int n, byte[] dest) {
        intToBytes4(n, dest, 0);
    }

    public static byte[] intToBytes4(int n) {
        byte[] bytes4 = new byte[4];
        intToBytes4(n, bytes4);
        return bytes4;
    }

    public static void intsToBytes(int[] ints, int offset,
                                   byte[] dest, int destOffset, int length) {
        for(int i = offset; i < offset + length; i++) {
            intToBytes4(ints[i], dest, destOffset + i * 4);
        }
    }

    public static void intsToBytes(int[] ints, byte[] dest) {
        intsToBytes(ints, 0, dest, 0, ints.length);
    }

    public static byte[] intsToBytes(int[] ints) {
        byte[] dest = new byte[ints.length * 4];
        intsToBytes(ints, 0, dest, 0, ints.length);
        return dest;
    }

    public static void bigIntToBytes32(BigInteger value, byte[] dest, int offset) {
        byte[] byteArr = value.toByteArray();

        if (byteArr.length == 32) {
            System.arraycopy(byteArr, 0, dest, offset, 32);
        } else {
            int start = (byteArr[0] == 0 && byteArr.length != 1) ? 1 : 0;
            int count = byteArr.length - start;

            if (count > 32) {
                throw new IllegalArgumentException(
                        "The length of value must not greater than 32: " + count);
            }

            System.arraycopy(byteArr, start, dest, offset + 32 - count, count);
        }
    }

    public static void bigIntToBytes32(BigInteger value, byte[] dest) {
        bigIntToBytes32(value, dest, 0);
    }

    public static byte[] bigIntToBytes32(BigInteger value) {
        byte[] bytes32 = new byte[32];
        bigIntToBytes32(value, bytes32);
        return bytes32;
    }

    public static void longToBytes8(long value, byte[] dest, int offset) {
        intToBytes4((int)(value >>> 32), dest, offset);
        intToBytes4((int)(value & 0xFFFFFFFFL), dest, offset + 4);
    }

    public static long bytes8ToLong(byte[] bytes8, int offset) {
        int high = bytes4ToInt(bytes8, offset);
        int low = bytes4ToInt(bytes8, offset + 4);
        return ((high & 0xFFFFFFFFL) << 32) | (low & 0xFFFFFFFFL);
    }

    public static byte[] copy(byte[] data, int offset, int length) {
        RangeUtil.nullAndBoundsCheck(data, offset, length);

        // Just return the original byte array for performance concern
        if (length == data.length) {
            return data;
        }

        byte[] copy = new byte[length];
        System.arraycopy(data, offset, copy, 0, length);
        return copy;
    }

    public static byte[] clone(byte[] data) {
        return data == null ? new byte[0] : data.clone();
    }

    public static byte[] concat(byte[] data1, int data1Offset, int data1Length,
                                byte[] data2, int data2Offset, int data2Length) {
        byte[] copy = new byte[data1Length + data2Length];
        System.arraycopy(data1, data1Offset, copy, 0, data1Length);
        System.arraycopy(data2, data2Offset, copy, data1Length, data2Length);
        return copy;
    }

    public static byte[] concat(byte[] data1, byte[] data2) {
        return concat(data1, 0, data1.length, data2, 0, data2.length);
    }

    // Format: 0x04<x-coordinate><y-coordinate>
    public static ECPoint pubKeyPoint(byte[] encodedPubKey) {
        if (encodedPubKey.length != Constants.SM2_PUBKEY_LEN) {
            throw new IllegalArgumentException(
                    "The encoded public key must be 65-bytes: "
                            + encodedPubKey.length);
        }

        if (encodedPubKey[0] != 0x04) {
            throw new IllegalArgumentException(
                    "The encoded public key must start with 0x04");
        }

        BigInteger x = toBigInt(copy(encodedPubKey, 1, 32));
        BigInteger y = toBigInt(copy(encodedPubKey, 33, 32));
        return new ECPoint(x, y);
    }

    public static byte[] pubKey(ECPoint pubPoint) {
        byte[] x = bigIntToBytes32(pubPoint.getAffineX());
        byte[] y = bigIntToBytes32(pubPoint.getAffineY());

        byte[] encoded = new byte[65];
        encoded[0] = 0x04;
        System.arraycopy(x, 0, encoded, 1, 32);
        System.arraycopy(y, 0, encoded, 33, 32);
        return encoded;
    }

    public static byte[] priKey(BigInteger priKeyValue) {
        return bigIntToBytes32(priKeyValue);
    }

    public static void checkId(byte[] id) {
        if (id.length >= 8192) {
            throw new IllegalArgumentException(
                    "The length of ID must be less than 8192-bytes");
        }
    }

    private CryptoUtils() { }
}
