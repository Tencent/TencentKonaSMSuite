/*
 * Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package com.tencent.kona.sun.security.ec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.spec.ECPoint;

/**
 * The test for EC operator.
 */
public class ECOperatorTest {

    private static final ECPoint DUMMY_GENERATOR = new ECPoint(
            BigInteger.valueOf(15), BigInteger.valueOf(13));

    // A simple testing curve y^2 = x^3 + 7 (mod 17).
    // The generator point is (15, 13), the order is 18 and the cofactor is 1.
    // See https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc
    // The points are:
    // (01, 05), (01, 12), (02, 07), (02, 10), (03, 00), (05, 08), (05, 09),
    // (06, 06), (06, 11), (08, 30), (08, 14), (10, 02), (10, 15),
    // (12, 01), (12, 16), (15, 04), (15, 13), Infinity
    private static final ECOperator DUMMY = new ECOperator(
            BigInteger.valueOf(0), BigInteger.valueOf(7), BigInteger.valueOf(17),
            DUMMY_GENERATOR, BigInteger.valueOf(18), 1);

    @Test
    public void testIsOnCurve() {
        // The infinity point always be on the curve.
        Assertions.assertTrue(DUMMY.isOnCurve(ECOperator.INFINITY));

        // The generator point must be on the curve.
        Assertions.assertTrue(DUMMY.isOnCurve(DUMMY.getGenerator()));

        Assertions.assertTrue(DUMMY.isOnCurve(new ECPoint(
                BigInteger.valueOf(1), BigInteger.valueOf(12))));
        Assertions.assertTrue(DUMMY.isOnCurve(new ECPoint(
                BigInteger.valueOf(3), BigInteger.valueOf(0))));

        Assertions.assertFalse(DUMMY.isOnCurve(new ECPoint(
                BigInteger.valueOf(5), BigInteger.valueOf(7))));
    }

    @Test
    public void testCheckOrder() {
        Assertions.assertTrue(DUMMY.checkOrder(ECOperator.INFINITY));
        Assertions.assertTrue(DUMMY.checkOrder(DUMMY_GENERATOR));
        Assertions.assertTrue(DUMMY.checkOrder(new ECPoint(
                BigInteger.valueOf(11), BigInteger.valueOf(1))));
    }

    @Test
    public void testAdd() {
        ECPoint sum = DUMMY.add(
                new ECPoint(BigInteger.valueOf(6), BigInteger.valueOf(11)),
                new ECPoint(BigInteger.valueOf(15), BigInteger.valueOf(4)));
        Assertions.assertEquals(BigInteger.valueOf(5), sum.getAffineX());
        Assertions.assertEquals(BigInteger.valueOf(9), sum.getAffineY());
    }

    @Test
    public void testAddInfinity() {
        ECPoint point = new ECPoint(
                BigInteger.valueOf(2), BigInteger.valueOf(7));

        ECPoint sum = DUMMY.add(point, ECOperator.INFINITY);
        Assertions.assertEquals(point.getAffineX(), sum.getAffineX());
        Assertions.assertEquals(point.getAffineY(), sum.getAffineY());

        sum = DUMMY.add(ECOperator.INFINITY, point);
        Assertions.assertEquals(point.getAffineX(), sum.getAffineX());
        Assertions.assertEquals(point.getAffineY(), sum.getAffineY());
    }

    @Test
    public void testSubtract() {
        ECPoint diff = DUMMY.subtract(
                new ECPoint(BigInteger.valueOf(6), BigInteger.valueOf(11)),
                new ECPoint(BigInteger.valueOf(15), BigInteger.valueOf(13)));
        Assertions.assertEquals(BigInteger.valueOf(5), diff.getAffineX());
        Assertions.assertEquals(BigInteger.valueOf(9), diff.getAffineY());
    }

    @Test
    public void testSubtractInfinity() {
        ECPoint point = new ECPoint(
                BigInteger.valueOf(2), BigInteger.valueOf(10));

        ECPoint diff = DUMMY.subtract(point, ECOperator.INFINITY);
        Assertions.assertEquals(point.getAffineX(), diff.getAffineX());
        Assertions.assertEquals(point.getAffineY(), diff.getAffineY());

        diff = DUMMY.subtract(ECOperator.INFINITY, point);
        Assertions.assertEquals(point.getAffineX(), diff.getAffineX());
        Assertions.assertEquals(point.getAffineY().negate(), diff.getAffineY());
    }

    @Test
    public void testMultiply() {
        ECPoint product = DUMMY.multiply(DUMMY_GENERATOR, 6);
        Assertions.assertEquals(BigInteger.valueOf(5), product.getAffineX());
        Assertions.assertEquals(BigInteger.valueOf(8), product.getAffineY());

        product = DUMMY.multiply(DUMMY_GENERATOR, 0);
        Assertions.assertEquals(ECOperator.INFINITY, product);

        // 18 is the order of this finite field.
        product = DUMMY.multiply(DUMMY_GENERATOR, 18);
        Assertions.assertEquals(ECOperator.INFINITY, product);
    }

    @Test
    public void testMultiplyInfinity() {
        ECPoint product = DUMMY.multiply(ECOperator.INFINITY, 6);
        Assertions.assertEquals(ECOperator.INFINITY, product);
    }
}
