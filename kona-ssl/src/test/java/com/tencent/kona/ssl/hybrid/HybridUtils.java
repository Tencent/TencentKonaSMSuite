/*
 * Copyright (C) 2022, 2023, Tencent. All rights reserved.
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

package com.tencent.kona.ssl.hybrid;

import com.tencent.kona.ssl.interop.FileCert;
import com.tencent.kona.ssl.interop.HashAlgorithm;
import com.tencent.kona.ssl.interop.KeyAlgorithm;
import com.tencent.kona.ssl.interop.SignatureAlgorithm;

public class HybridUtils {

    /* ***** RSA START ***** */
    public static final FileCert RSA_CA = new FileCert(
            KeyAlgorithm.RSA, SignatureAlgorithm.RSA, HashAlgorithm.SHA256,
            "hybrid",
            "rsa-ca.crt",
            "rsa-ca.key");

    public static final FileCert RSA_INTCA = new FileCert(
            KeyAlgorithm.RSA, SignatureAlgorithm.RSA, HashAlgorithm.SHA256,
            "hybrid",
            "rsa-intca.crt",
            "rsa-intca.key");

    public static final FileCert RSA_SERVER = new FileCert(
            KeyAlgorithm.RSA, SignatureAlgorithm.RSA, HashAlgorithm.SHA256,
            "hybrid",
            "rsa-server.crt",
            "rsa-server.key");

    public static final FileCert RSA_CLIENT = new FileCert(
            KeyAlgorithm.RSA, SignatureAlgorithm.RSA, HashAlgorithm.SHA256,
            "hybrid",
            "rsa-client.crt",
            "rsa-client.key");
    /* ***** RSA END ***** */

    /* ***** EC START ***** */
    public static final FileCert EC_CA = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256,
            "hybrid",
            "ec-ca.crt",
            "ec-ca.key");

    public static final FileCert EC_INTCA = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256,
            "hybrid",
            "ec-intca.crt",
            "ec-intca.key");

    public static final FileCert EC_SERVER = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256,
            "hybrid",
            "ec-server.crt",
            "ec-server.key");

    public static final FileCert EC_CLIENT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256,
            "hybrid",
            "ec-client.crt",
            "ec-client.key");
    /* ***** EC END ***** */

    /* ***** SM START ***** */
    public static final FileCert SM_CA = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "hybrid",
            "sm-ca.crt",
            "sm-ca.key");

    public static final FileCert SM_INTCA = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "hybrid",
            "sm-intca.crt",
            "sm-intca.key");

    public static final FileCert SM_SERVER_SIGN = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "hybrid",
            "sm-server-sign.crt",
            "sm-server-sign.key");

    public static final FileCert SM_CLIENT_SIGN = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "hybrid",
            "sm-client-sign.crt",
            "sm-client-sign.key");

    public static final FileCert SM_SERVER_ENC = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "hybrid",
            "sm-server-enc.crt",
            "sm-server-enc.key");

    public static final FileCert SM_CLIENT_ENC = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "hybrid",
            "sm-client-enc.crt",
            "sm-client-enc.key");
    /* ***** SM END ***** */
}
