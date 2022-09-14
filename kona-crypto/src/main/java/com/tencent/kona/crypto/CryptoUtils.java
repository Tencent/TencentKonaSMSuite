package com.tencent.kona.crypto;

import java.math.BigInteger;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.spec.ECPoint;
import java.util.Arrays;

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

    public static void intToBytes32(BigInteger value, byte[] dest, int offset) {
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

    public static void intToBytes32(BigInteger value, byte[] dest) {
        intToBytes32(value, dest, 0);
    }

    public static byte[] intToBytes32(BigInteger value) {
        byte[] bytes32 = new byte[32];
        intToBytes32(value, bytes32);
        return bytes32;
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

    public static void reset(byte[] bytes, int offset, int length) {
        if (bytes != null && bytes.length > 0) {
            Arrays.fill(bytes, offset, length, (byte) 0x00);
        }
    }

    public static void reset(byte[] bytes) {
        reset(bytes, 0, bytes.length);
    }

    public static int ciphertextLen(int plaintextLen) {
        return plaintextLen + Constants.SM4_BLOCK_SIZE - plaintextLen % Constants.SM4_BLOCK_SIZE;
    }

    public static void checkKey(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("Missing key");
        }

        if (key.length == 0) {
            throw new IllegalArgumentException("Empty key");
        }
    }

    public static void checkKey(BigInteger key) {
        if (key == null) {
            throw new IllegalArgumentException("Missing key");
        }
    }

    public static void checkKey(ECPoint pubKey) {
        if (pubKey == null || pubKey.getAffineX() == null
                || pubKey.getAffineY() == null) {
            throw new IllegalArgumentException("Missing key");
        }
    }

    // Format: 0x04<x-coordinate><y-coordinate>
    public static ECPoint pubKeyPoint(byte[] pubKey) {
        if (pubKey.length != Constants.SM2_PUBKEY_LEN) {
            throw new IllegalArgumentException(
                    "The uncompressed raw public key must be 65-byte length: "
                            + pubKey.length);
        }

        BigInteger x = toBigInt(copy(pubKey, 1, 32));
        BigInteger y = toBigInt(copy(pubKey, 33, 32));
        return new ECPoint(x, y);
    }

    public static byte[] pubKey(ECPoint pubKeyPoint) {
        byte[] x = coordinate(pubKeyPoint.getAffineX().toByteArray());
        byte[] y = coordinate(pubKeyPoint.getAffineY().toByteArray());

        byte[] pubKey = new byte[Constants.SM2_PUBKEY_LEN];
        byte[] flag = toBytes("04");
        System.arraycopy(flag, 0, pubKey, 0, flag.length);
        System.arraycopy(x, 0, pubKey, flag.length, x.length);
        System.arraycopy(y, 0, pubKey, flag.length + x.length, y.length);
        return pubKey;
    }

    private static byte[] coordinate(byte[] coordinate) {
        return adjustBytes(coordinate, Constants.SM2_PUBKEY_AFFINE_LEN);
    }

    public static byte[] priKey(BigInteger priKeyValue) {
        return adjustBytes(priKeyValue.toByteArray(), Constants.SM2_PRIKEY_LEN);
    }

    private static byte[] adjustBytes(byte[] origBytes, int length) {
        byte[] adjusted = origBytes;

        if (origBytes.length < length) {
            adjusted = new byte[length];
            System.arraycopy(
                    origBytes, 0,
                    adjusted, adjusted.length - origBytes.length,
                    origBytes.length);
        } else if (origBytes.length == length + 1
                && origBytes[0] == 0x00) {
            adjusted = new byte[length];
            System.arraycopy(
                    origBytes, 1,
                    adjusted, 0,
                    origBytes.length - 1);
        }

        return adjusted;
    }

    private CryptoUtils() { }
}
