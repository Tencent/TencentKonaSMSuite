/*
 * Copyright (C) 2022, 2024, Tencent. All rights reserved.
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

import java.nio.file.Path;
import java.nio.file.Paths;

/*
 * OpenSSL/Tongsuo product.
 * This product is used for testing TLCP/NTLS/GMTLS.
 */
public class Tongsuo extends AbstractProduct {

    public static final Tongsuo DEFAULT = new Tongsuo(
            "Tongsuo",
            System.getProperty("test.tongsuo.path", "tongsuo"));

    private final String name;
    private final Path path;

    public Tongsuo(String name, Path path) {
        this.name = name;
        this.path = path;
    }

    public Tongsuo(String name, String path) {
        this(name, Paths.get(path));
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Path getPath() {
        return path;
    }
}
