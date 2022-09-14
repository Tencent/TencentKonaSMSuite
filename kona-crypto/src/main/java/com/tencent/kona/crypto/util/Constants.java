package com.tencent.kona.crypto.util;

import com.tencent.kona.crypto.CryptoUtils;
import com.tencent.kona.crypto.spec.SM2ParameterSpec;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;

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

    public static final int SM2_PRIKEY_LEN = 32;

    // The length of raw SM2 signature, exactly the values of R and S.
    public static final int SM2_SIGN_RS_LEN = 64;

    public static final int SM3_BLOCK_SIZE = 32;
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

    public static final ECDomainParameters SM2_DOMAIN = sm2DomainParams();

    private static ECDomainParameters sm2DomainParams() {
        SM2ParameterSpec sm2ParamSpec = SM2ParameterSpec.instance();
        EllipticCurve sm2Curve = sm2ParamSpec.getCurve();
        ECFieldFp sm2Filed = (ECFieldFp) sm2Curve.getField();
        BigInteger order = sm2ParamSpec.getOrder();
        ECCurve curve = new ECCurve.Fp(
                sm2Filed.getP(),
                sm2Curve.getA(),
                sm2Curve.getB(),
                order,
                BigInteger.valueOf(sm2ParamSpec.getCofactor()));

        java.security.spec.ECPoint sm2Generator = sm2ParamSpec.getGenerator();
        ECPoint generator = curve.createPoint(
                sm2Generator.getAffineX(), sm2Generator.getAffineY());
        return new ECDomainParameters(curve, generator, order);
    }
}
