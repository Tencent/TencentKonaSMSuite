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

package com.tencent.kona.ssl;

import com.tencent.kona.crypto.CryptoInsts;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

/**
 * The utilities for this provider.
 */
public class SSLUtils {

    /* ***** System properties start ***** */

    public static String getPropCertListFormat() {
        return System.getProperty("com.tencent.kona.ssl.certListFormat");
    }

    // SIGN|ENC|CA, SIGN|CA|ENC
    public static void setPropCertListFormat(String format) {
        String certListFormat = format == null || format.length() == 0
                ? "" : format.toUpperCase(Locale.ENGLISH);
        System.setProperty("com.tencent.kona.ssl.certListFormat", certListFormat);
    }

    /* ***** System properties end ***** */

    public static KeyPairGenerator getECKeyPairGenerator(String namedGroup)
            throws NoSuchAlgorithmException {
        String algorithm = "curvesm2".equalsIgnoreCase(namedGroup)
                ? "SM2" : "EC";
        return CryptoInsts.getKeyPairGenerator(algorithm);
    }
}
