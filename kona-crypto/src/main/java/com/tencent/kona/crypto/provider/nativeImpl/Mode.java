/*
 * Copyright (C) 2024, THL A29 Limited, a Tencent company. All rights reserved.
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

package com.tencent.kona.crypto.provider.nativeImpl;

/**
 * The block cipher operation modes.
 */
enum Mode {

    CBC("CBC"), CTR("CTR"), ECB("ECB"), GCM("GCM");

    final String name;

    Mode(String name) {
        this.name = name;
    }

    static boolean isCBC(String mode) {
        return CBC.name.equalsIgnoreCase(mode);
    }

    static boolean isCTR(String mode) {
        return CTR.name.equalsIgnoreCase(mode);
    }

    static boolean isECB(String mode) {
        return ECB.name.equalsIgnoreCase(mode);
    }

    static boolean isGCM(String mode) {
        return GCM.name.equalsIgnoreCase(mode);
    }

    static Mode getMode(String mode) {
        switch (mode) {
            case "CBC": return CBC;
            case "CTR": return CTR;
            case "ECB": return ECB;
            case "GCM": return GCM;
            default: return null;
        }
    }
}
