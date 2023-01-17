package com.tencent.kona.crypto.util;

import com.tencent.kona.crypto.CryptoUtils;

import java.math.BigInteger;

public class Constants {

    public static final BigInteger TWO = BigInteger.valueOf(2);
    public static final BigInteger THREE = BigInteger.valueOf(3);

    public static final String JDK_VERSION = CryptoUtils.privilegedGetProperty(
            "java.specification.version");

    public static final String JDK_VENDOR = CryptoUtils.privilegedGetProperty(
            "java.specification.vendor");

    // The length of uncompressed SM2 public key,
    // exactly a EC point's coordinates (x, y).
    // The hex format is 04||x||y
    public static final int SM2_PUBKEY_LEN = 65;

    // The length of the affine coordinate.
    public static final int SM2_PUBKEY_AFFINE_LEN = 32;

    public static final int SM2_CURVE_FIELD_SIZE = 32;

    public static final int SM2_PRIKEY_LEN = 32;

    public static final int SM3_BLOCK_SIZE = 64;
    public static final int SM3_DIGEST_LEN = 32;
    public static final int SM3_HMAC_LEN = 32;

    public static final int SM4_BLOCK_SIZE = 16;
    public static final int SM4_KEY_SIZE = 16;
    public static final int SM4_IV_LEN = 16;
    public static final int SM4_GCM_IV_LEN = 12;
    public static final int SM4_GCM_TAG_LEN = 16;

    // The default ID: 1234567812345678
    private static final byte[] DEFAULT_ID
            = CryptoUtils.toBytes("31323334353637383132333435363738");

    public static byte[] defaultId() {
        return DEFAULT_ID.clone();
    }
}
