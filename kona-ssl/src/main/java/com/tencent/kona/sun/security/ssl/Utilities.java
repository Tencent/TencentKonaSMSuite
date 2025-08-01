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

package com.tencent.kona.sun.security.ssl;

import javax.net.ssl.SSLParameters;

public class Utilities extends com.tencent.kona.sun.security.util.Utilities {

    public static final boolean SUPPORT_ALPN = supportALPN();

    private static boolean supportALPN() {
        boolean supported;
        try {
            SSLParameters.class.getMethod("getApplicationProtocols");
            supported = true;
        } catch (NoSuchMethodException e) {
            supported = false;
        }
        return supported;
    }

    static <T> boolean contains(T[] array, T item) {
        for (T t : array) {
            if (item.equals(t)) {
                return true;
            }
        }

        return false;
    }
}
