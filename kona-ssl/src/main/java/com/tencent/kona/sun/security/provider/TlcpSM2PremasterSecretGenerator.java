/*
 * Copyright (c) 2005, 2021, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.tencent.kona.sun.security.provider;

import com.tencent.kona.sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public final class TlcpSM2PremasterSecretGenerator extends KeyGeneratorSpi {

    private static final String MSG = "TlcpSM2PremasterSecretGenerator must be "
        + "initialized using a TlsRsaPremasterSecretParameterSpec";

    private TlsRsaPremasterSecretParameterSpec spec;
    private SecureRandom random;

    protected void engineInit(SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    @SuppressWarnings("deprecation")
    protected void engineInit(AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidAlgorithmParameterException {
        if (!(params instanceof TlsRsaPremasterSecretParameterSpec)) {
            throw new InvalidAlgorithmParameterException(MSG);
        }

        this.spec = (TlsRsaPremasterSecretParameterSpec) params;
        this.random = random;
    }

    protected void engineInit(int keysize, SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    // Only can be used in client side to generate TLCP SM2 premaster secret.
    protected SecretKey engineGenerateKey() {
        if (spec == null) {
            throw new IllegalStateException(
                    "TlcpSM2PremasterSecretGenerator must be initialized");
        }

        byte[] b = spec.getEncodedSecret();
        if (b == null) {
            if (random == null) {
                random = new SecureRandom();
            }
            b = new byte[48];
            random.nextBytes(b);
        }
        b[0] = (byte)spec.getMajorVersion();
        b[1] = (byte)spec.getMinorVersion();

        try {
            return new SecretKeySpec(b, "TlcpSM2PremasterSecret");
        } finally {
            Arrays.fill(b, (byte)0);
        }
    }
}
