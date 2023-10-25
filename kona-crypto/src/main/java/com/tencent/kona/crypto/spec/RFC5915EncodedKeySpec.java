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

import java.security.spec.EncodedKeySpec;

/**
 * An encoded EC private key in compliant with RFC 5915.
 *
 * <pre>
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *   privateKey     OCTET STRING,
 *   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *   publicKey  [1] BIT STRING OPTIONAL
 * }
 * </pre>
 */
public final class RFC5915EncodedKeySpec extends EncodedKeySpec {

    /**
     * Creates a new {@code RFC5915EncodedKeySpec} with the given encoded key.
     *
     * @param encodedKey the encoded key in compliant with RFC 5915.
     *
     * @exception NullPointerException if {@code encodedKey} is null.
     */
    public RFC5915EncodedKeySpec(byte[] encodedKey) {
        super(encodedKey);
    }

    /**
     * Returns {@code RFC5915} as the format.
     *
     * @return the format name.
     */
    @Override
    public String getFormat() {
        return "RFC5915";
    }
}
