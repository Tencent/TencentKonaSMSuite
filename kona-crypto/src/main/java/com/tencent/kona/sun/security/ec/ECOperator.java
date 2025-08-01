/*
 * Copyright (C) 2022, 2025, Tencent. All rights reserved.
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

package com.tencent.kona.sun.security.ec;

import com.tencent.kona.crypto.spec.SM2ParameterSpec;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;
import static java.security.spec.ECPoint.POINT_INFINITY;

import static com.tencent.kona.crypto.CryptoUtils.toBigInt;

/*
 * The operator for EC point arithmetic operations.
 * The main algorithms refer to the wikipedia page:
 * https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
 *
 * CAUTION: Just for demonstration purposes, don't use it in real products.
 */
@Deprecated
public class ECOperator {

    // A pre-defined operator for SM2.
    public static final ECOperator SM2 = new ECOperator(
            SM2ParameterSpec.instance());

    // A pre-defined operator for secp256r1.
    public static final ECOperator SECP256R1 = new ECOperator(
            toBigInt("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
            toBigInt("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
            toBigInt("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
            new ECPoint(
                    toBigInt("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
                    toBigInt("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")),
            toBigInt("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
            1);

    // A pre-defined operator for secp384r1.
    public static final ECOperator SECP384R1 = new ECOperator(
            toBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC"),
            toBigInt("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"),
            toBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"),
            new ECPoint(
                    toBigInt("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"),
                    toBigInt("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F")),
            toBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"),
            1);

    // A pre-defined operator for secp521r1.
    public static final ECOperator SECP521R1 = new ECOperator(
            toBigInt("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC"),
            toBigInt("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"),
            toBigInt("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
            new ECPoint(
                    toBigInt("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"),
                    toBigInt("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650")),
            toBigInt("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"),
            1);

    // A pre-defined operator for secp256k1.
    public static final ECOperator SECP256K1 = new ECOperator(
            toBigInt("0000000000000000000000000000000000000000000000000000000000000000"),
            toBigInt("0000000000000000000000000000000000000000000000000000000000000007"),
            toBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
            new ECPoint(
                    toBigInt("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
                    toBigInt("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")),
            toBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
            1);

    private final static BigInteger TWO = BigInteger.valueOf(2);
    private final static BigInteger THREE = BigInteger.valueOf(3);

    private final BigInteger a;
    private final BigInteger b;
    private final BigInteger prime;

    private final EllipticCurve curve;

    private final ECPoint generator;
    private final BigInteger order;
    private final int cofactor;

    public ECOperator(ECParameterSpec paramSpec) {
        curve = paramSpec.getCurve();
        a = curve.getA();
        b = curve.getB();
        prime = ((ECFieldFp) curve.getField()).getP();

        generator = paramSpec.getGenerator();
        order = paramSpec.getOrder();
        cofactor = paramSpec.getCofactor();
    }

    public ECOperator(BigInteger a, BigInteger b, BigInteger prime,
                      ECPoint generator, BigInteger order, int cofactor) {
        this.a = a;
        this.b = b;
        this.prime = prime;

        curve = new EllipticCurve(new ECFieldFp(prime), a, b);

        this.generator = generator;
        this.order = order;
        this.cofactor = cofactor;
    }

    public BigInteger getA() {
        return a;
    }

    public BigInteger getB() {
        return b;
    }

    public BigInteger getPrime() {
        return prime;
    }

    public ECPoint getGenerator() {
        return generator;
    }

    public BigInteger getOrder() {
        return order;
    }

    public int getCofactor() {
        return cofactor;
    }

    public EllipticCurve getCurve() {
        return curve;
    }

    /*
     * Check if a specific EC point is on the curve.
     */
    public boolean isOnCurve(ECPoint p) {
        if (isInfinity(p)) {
            return true;
        }

        return lhs(p.getAffineY()).equals(rhs(p.getAffineX()));
    }

    /*
     * Check if the order of a specific EC point is same as that in the finite field.
     */
    public boolean checkOrder(ECPoint p) {
        return isInfinity(multiply(p, order));
    }

    /*
     * The EC point addition.
     *
     * (P.x, P.y) = (P1.x, P1.y) + (P2.x, P2.y)
     * --> lambda = (P2.y - P1.y) / (P2.x - P1.x)
     *     P.x = lambda ^ 2 - P1.x - P2.x
     *     P.y = lambda * (P1.x - P.x) - P1.y
     */
    public ECPoint add(ECPoint p1, ECPoint p2) {
        if (isInfinity(p1)) {
            return isInfinity(p2)
                    ? POINT_INFINITY
                    : new ECPoint(p2.getAffineX(), p2.getAffineY());
        }

        if (isInfinity(p2)) {
            return new ECPoint(p1.getAffineX(), p1.getAffineY());
        }

        BigInteger lambda;
        if (p1.getAffineX().subtract(p2.getAffineX()).mod(prime).equals(ZERO)) {
            if (p1.getAffineY().subtract(p2.getAffineY()).mod(prime).equals(ZERO)) {
                // Here, p1 == p2
                lambda = lambda(p1, p2);
                if (lambda == null) {
                    return POINT_INFINITY;
                }
            } else {
                return POINT_INFINITY;
            }
        } else {
            BigInteger nom = p2.getAffineY().subtract(p1.getAffineY());
            BigInteger denom = p2.getAffineX().subtract(p1.getAffineX());
            lambda = nom.multiply(denom.modInverse(prime)).mod(prime);
        }

        return calcPoint(p1, p2, lambda);
    }

    /*
     * The EC point doubling.
     *
     * (Q.x, Q.y) = 2 * (P.x, P.y)
     * --> lambda = (3 * P.x * P.x + a) / (2 * P.y)
     *     Q.x = lambda ^ 2 - P.x - P.x
     *     Q.y = lambda * (P.x - Q.x) - P.y
     */
    public ECPoint doubling(ECPoint p) {
        if (isInfinity(p)) {
            return p;
        }

        BigInteger denom = p.getAffineY().multiply(TWO).mod(prime);
        if (ZERO.equals(denom)) {
            return POINT_INFINITY;
        }

        BigInteger lambda = lambda(p, p);
        if (lambda == null) {
            return POINT_INFINITY;
        }

        return calcPoint(p, p, lambda);
    }

    private BigInteger lambda(ECPoint p1, ECPoint p2) {
        BigInteger denom = p1.getAffineY().add(p1.getAffineY());
        if (ZERO.equals(denom)) {
            return null;
        }

        BigInteger nom = p1.getAffineX().multiply(p1.getAffineX()).mod(prime)
                .multiply(THREE).mod(prime)
                .add(a);
        return nom.multiply(denom.modInverse(prime)).mod(prime);
    }

    /*
     * P.x = lambda ^ 2 - P1.x - P2.x
     * P.y = lambda * (P1.x - P.x) - P1.y
     */
    private ECPoint calcPoint(ECPoint p1, ECPoint p2, BigInteger lambda) {
        BigInteger x = lambda
                .multiply(lambda).mod(prime)
                .subtract(p1.getAffineX())
                .subtract(p2.getAffineX())
                .mod(prime);
        BigInteger y = lambda
                .multiply(p1.getAffineX().subtract(x)).mod(prime)
                .subtract(p1.getAffineY())
                .mod(prime);
        return new ECPoint(x, y);
    }

    /*
     * The EC point subtraction.
     */
    public ECPoint subtract(ECPoint p1, ECPoint p2) {
        return add(p1, negate(p2));
    }

    /*
     * The EC point multiplication.
     */
    public ECPoint multiply(ECPoint p, BigInteger k) {
        return montgomeryLadder(p, k);
    }

    // Montgomery ladder algorithm
    private ECPoint montgomeryLadder(ECPoint p, BigInteger k) {
        ECPoint p0 = POINT_INFINITY;
        ECPoint p1 = p;
        int idx = k.bitLength();

        while (idx >= 0) {
            if (k.testBit(idx--)) {
                p0 = add(p0, p1);
                p1 = doubling(p1);
            } else {
                p1 = add(p0, p1);
                p0 = doubling(p0);
            }
        }

        return p0;
    }

    // Double-and-Add algorithm
    private ECPoint doubleAndAdd(ECPoint p, BigInteger k) {
        if (isInfinity(p) || k.equals(ZERO)) {
            return POINT_INFINITY;
        }

        if (k.equals(ONE)) {
            return p;
        }

        int i = k.bitLength() - 2;
        ECPoint result = p;
        while(i >= 0) {
            result = doubling(result);
            if (k.testBit(i)) {
                result = add(result, p);
            }
            i = i - 1;
        }

        return result;
    }

    public ECPoint multiply(ECPoint p, long k) {
        return multiply(p, BigInteger.valueOf(k));
    }

    /*
     * The EC point multiplication with the generator.
     */
    public ECPoint multiply(BigInteger k) {
        return multiply(generator, k);
    }

    public ECPoint multiply(long k) {
        return multiply(generator, k);
    }

    // The left-hand side of the equation.
    private BigInteger lhs(BigInteger y) {
        return y.modPow(TWO, prime);
    }

    // The right-hand side of the equation.
    private BigInteger rhs(BigInteger x) {
        return x.modPow(THREE, prime).add(a.multiply(x)).add(b).mod(prime);
    }

    private static boolean isInfinity(ECPoint p) {
        return p.equals(POINT_INFINITY);
    }

    private static ECPoint negate(ECPoint p) {
        return isInfinity(p)
                ? POINT_INFINITY
                : new ECPoint(p.getAffineX(), p.getAffineY().negate());
    }
}
