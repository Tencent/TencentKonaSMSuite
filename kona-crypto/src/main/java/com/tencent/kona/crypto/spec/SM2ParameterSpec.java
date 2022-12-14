package com.tencent.kona.crypto.spec;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import static com.tencent.kona.crypto.CryptoUtils.toBigInt;

/**
 * SM2 parameter spec. The EC-related parameters are defined by China's
 * specification GB/T 32918.5-2017.
 */
public class SM2ParameterSpec extends ECParameterSpec {

    private static class InstanceHolder {

        private static final SM2ParameterSpec INSTANCE = new SM2ParameterSpec();
    }

    public static SM2ParameterSpec instance() {
        return InstanceHolder.INSTANCE;
    }

    public static final EllipticCurve CURVE = curve();
    public static final ECPoint GENERATOR = generator();
    public static final BigInteger ORDER = order();
    public static final BigInteger COFACTOR = cofactor();
    public static final String OID = "1.2.156.10197.1.301";

    // 0x06082A811CCF5501822D
    // OBJECT IDENTIFIER 1.2.156.10197.1.301
    private static final byte[] ENCODED = new byte[] {
            6, 8, 42, -127, 28, -49, 85, 1, -126, 45 };

    private SM2ParameterSpec() {
        super(CURVE, GENERATOR, ORDER, COFACTOR.intValue());
    }

    private static EllipticCurve curve() {
        return new EllipticCurve(
                new ECFieldFp(toBigInt(
                        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF")),
                toBigInt("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"),
                toBigInt("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"),
                null);
    }

    private static ECPoint generator() {
        return new ECPoint(
                toBigInt("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"),
                toBigInt("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"));
    }

    private static BigInteger order() {
        return toBigInt("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123");
    }

    private static BigInteger cofactor() {
        return BigInteger.ONE;
    }

    public String oid() {
        return OID;
    }

    public byte[] encoded() {
        return ENCODED.clone();
    }

    @Override
    public String toString() {
        return "SM2 (" + OID + ")";
    }
}
