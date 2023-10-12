/*
 * Copyright (C) 2023, THL A29 Limited, a Tencent company. All rights reserved.
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
import com.tencent.kona.sun.security.ec.point.AffinePoint;
import com.tencent.kona.sun.security.ec.point.Point;
import com.tencent.kona.sun.security.util.math.IntegerFieldModuloP;
import com.tencent.kona.sun.security.util.math.IntegerModuloP;
import com.tencent.kona.sun.security.util.math.intpoly.IntegerPolynomialSM2;
import com.tencent.kona.sun.security.util.math.intpoly.SM2OrderField;

import java.security.spec.ECPoint;

/**
 * Elliptic curve point arithmetic for SM2.
 */
public class SM2Operations extends ECOperations {

    public static final SM2Operations SM2OPS = new SM2Operations(
            IntegerPolynomialSM2.ONE.getElement(SM2ParameterSpec.CURVE.getB()),
            SM2OrderField.ONE);

    public SM2Operations(IntegerModuloP b, IntegerFieldModuloP orderField) {
        super(b, orderField);
    }

    public static ECPoint toECPoint(Point point) {
        AffinePoint affPoint = point.asAffine();
        return new ECPoint(
                affPoint.getX().asBigInteger(),
                affPoint.getY().asBigInteger());
    }
}
