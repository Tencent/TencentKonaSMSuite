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

package com.tencent.kona.crypto.spec;

import com.tencent.kona.crypto.CryptoUtils;

import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

/**
 * A SM2 public key with the specified value.
 */
public class SM2PublicKeySpec extends ECPublicKeySpec {

    /**
     * Create a new {@code SM2PublicKeySpec}.
     *
     * @param pubPoint the public point.
     */
    public SM2PublicKeySpec(ECPoint pubPoint) {
        super(pubPoint, SM2ParameterSpec.instance());
    }

    /**
     * Create a new {@code SM2PublicKeySpec}.
     *
     * @param encodedPubPoint the public point encoded in the format {@code 0x04|x|y}.
     *                        Here, {@code x} and {@code y} are the point coordinates.
     */
    public SM2PublicKeySpec(byte[] encodedPubPoint) {
        this(CryptoUtils.pubKeyPoint(encodedPubPoint));
    }
}
