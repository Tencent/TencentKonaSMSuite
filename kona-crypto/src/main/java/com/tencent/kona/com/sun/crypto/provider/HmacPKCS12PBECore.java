/*
 * Copyright (c) 2003, 2023, Oracle and/or its affiliates. All rights reserved.
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

package com.tencent.kona.com.sun.crypto.provider;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

import com.tencent.kona.jdk.internal.misc.SharedSecretsUtil;
import com.tencent.kona.sun.security.util.PBEUtil;

/**
 * This is an implementation of the HMAC algorithms as defined
 * in PKCS#12 v1.1 standard (see RFC 7292 Appendix B.4).
 *
 * @author Valerie Peng
 */
public abstract class HmacPKCS12PBECore extends HmacCore {

    private final String algorithm;
    private final int bl;

    /**
     * Standard constructor, creates a new HmacSHA1 instance.
     */
    public HmacPKCS12PBECore(String algorithm, int bl) throws NoSuchAlgorithmException {
        super(algorithm, bl);
        this.algorithm = algorithm;
        this.bl = bl;
    }

    /**
     * Initializes the HMAC with the given secret key and algorithm parameters.
     *
     * @param key the secret key.
     * @param params the algorithm parameters.
     *
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this MAC.
     * @exception InvalidAlgorithmParameterException if the given algorithm
     * parameters are inappropriate for this MAC.
     */
    protected void engineInit(Key key, AlgorithmParameterSpec params)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
        char[] password = null;
        byte[] derivedKey = null;
        SecretKeySpec cipherKey = null;
        PBEKeySpec keySpec = PBEUtil.getPBAKeySpec(key, params);
        try {
            password = keySpec.getPassword();
            derivedKey = PKCS12PBECipherCoreUtil.derive(
                    password, keySpec.getSalt(),
                    keySpec.getIterationCount(), engineGetMacLength(),
                    PKCS12PBECipherCoreUtil.MAC_KEY, algorithm, bl);
            cipherKey = new SecretKeySpec(derivedKey, "HmacSHA1");
            super.engineInit(cipherKey, null);
        } finally {
            if (cipherKey != null) {
                SharedSecretsUtil.cryptoSpecClearSecretKeySpec(cipherKey);
            }
            if (derivedKey != null) {
                Arrays.fill(derivedKey, (byte) 0);
            }
            if (password != null) {
                Arrays.fill(password, '\0');
            }
            keySpec.clearPassword();
        }
    }
}
