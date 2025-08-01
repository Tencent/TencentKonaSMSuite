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

package com.tencent.kona.ssl.tlcp;

import com.tencent.kona.ssl.interop.FileCert;
import com.tencent.kona.ssl.interop.HashAlgorithm;
import com.tencent.kona.ssl.interop.KeyAlgorithm;
import com.tencent.kona.ssl.interop.SignatureAlgorithm;

/**
 * The utilities for testing TLCP.
 */
public class TlcpUtils {

    public static final FileCert CA_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "tlcp",
            "tlcp-ca.crt",
            "tlcp-ca.key");

    public static final FileCert INTCA_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "tlcp",
            "tlcp-intca.crt",
            "tlcp-intca.key");

    // sign and enc cert (Server)
    public static final FileCert SERVER_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "tlcp",
            "tlcp-server.crt",
            "tlcp-server.key");

    // sign and enc cert (Client)
    public static final FileCert CLIENT_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "tlcp",
            "tlcp-client.crt",
            "tlcp-client.key");

    // sign cert (Server)
    public static final FileCert SERVER_SIGN_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "tlcp",
            "tlcp-server-sign.crt",
            "tlcp-server-sign.key");

    // sign cert (Client)
    public static final FileCert CLIENT_SIGN_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "tlcp",
            "tlcp-client-sign.crt",
            "tlcp-client-sign.key");

    // enc cert (Server)
    public static final FileCert SERVER_ENC_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "tlcp",
            "tlcp-server-enc.crt",
            "tlcp-server-enc.key");

    // enc cert (Client)
    public static final FileCert CLIENT_ENC_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "tlcp",
            "tlcp-client-enc.crt",
            "tlcp-client-enc.key");
}
