/*
 * Copyright (C) 2022, 2023, Tencent. All rights reserved.
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

package com.tencent.kona.crypto.provider;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidParameterException;
import java.security.spec.AlgorithmParameterSpec;

public final class SM4GenParameterSpec implements AlgorithmParameterSpec {

    private final Class<? extends AlgorithmParameterSpec> paramSpecClass;

    public SM4GenParameterSpec(
            Class<? extends AlgorithmParameterSpec> paramSpecClass) {
        if (paramSpecClass != IvParameterSpec.class
                && paramSpecClass != GCMParameterSpec.class) {
            throw new InvalidParameterException(
                    "Only IvParameterSpec and GCMParameterSpec are supported");
        }

        this.paramSpecClass = paramSpecClass;
    }

    public Class<? extends AlgorithmParameterSpec> getParamSpecClass() {
        return paramSpecClass;
    }
}
