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

package com.tencent.kona.ssl.interop;

public enum ContextProtocol {

    TLS("TLS"),
    TLCP("TLCP"),
    TLCP11("TLCPv1.1");

    public final String name;

    private ContextProtocol(String name) {
        this.name = name;
    }

    public String toString() {
        return name;
    }

    public static ContextProtocol contextProtocol(String name) {
        for (ContextProtocol contextProtocol : values()) {
            if (contextProtocol.name.equals(name)) {
                return contextProtocol;
            }
        }

        return null;
    }
}
