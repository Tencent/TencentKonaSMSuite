/*
 * Copyright (C) 2022, 2026, Tencent. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. Tencent designates
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

    // When true, fall back to the legacy TLCP double-certificate handling:
    // single-certificate lists are accepted (one cert serving both roles),
    // sign/enc roles are assigned purely by position with lenient, non-
    // exclusive keyUsage checks, and no same-identity / distinct-key binding
    // is enforced.
    //
    // SECURITY: enabling this re-opens the client-impersonation weakness where
    // possession of only the peer's encryption key is sufficient to be
    // authenticated as that peer. Use it only as an interop break-glass.
    public static boolean getPropTlcpDualCertCompat() {
        return Boolean.getBoolean("com.tencent.kona.ssl.tlcpDualCertCompat");
    }

    /* ***** System properties end ***** */
}
