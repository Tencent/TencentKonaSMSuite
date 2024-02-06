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

import com.tencent.kona.sun.security.internal.interfaces.TlsMasterSecret;
import com.tencent.kona.sun.security.internal.spec.TlsMasterSecretParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public final class TlcpMasterSecretGenerator extends KeyGeneratorSpi {

    private final static String MSG = "TlcpMasterSecretGenerator must be "
            + "initialized using a TlsMasterSecretParameterSpec";

    private TlsMasterSecretParameterSpec spec;

    private int protocolVersion;

    @Override
    protected void engineInit(SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidAlgorithmParameterException {
        if (!(params instanceof TlsMasterSecretParameterSpec)) {
            throw new InvalidAlgorithmParameterException(MSG);
        }
        this.spec = (TlsMasterSecretParameterSpec) params;
        if (!"RAW".equals(spec.getPremasterSecret().getFormat())) {
            throw new InvalidAlgorithmParameterException(
                    "Key format must be RAW");
        }
        protocolVersion = (spec.getMajorVersion() << 8)
                | spec.getMinorVersion();
        if (protocolVersion != 0x0101) {
            throw new InvalidAlgorithmParameterException(
                "Only TLCP 1.1 supported");
        }
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    @Override
    protected SecretKey engineGenerateKey() {
        if (spec == null) {
            throw new IllegalStateException(
                    "TlcpMasterSecretGenerator must be initialized");
        }
        SecretKey premasterKey = spec.getPremasterSecret();
        byte[] premaster = premasterKey.getEncoded();

        int premasterMajor, premasterMinor;
        if (premasterKey.getAlgorithm().equals("TlsRsaPremasterSecret")) {
            // RSA
            premasterMajor = premaster[0] & 0xff;
            premasterMinor = premaster[1] & 0xff;
        } else {
            // DH, KRB5, others
            premasterMajor = -1;
            premasterMinor = -1;
        }

        byte[] master;
        try {
            byte[] label;
            byte[] seed;
            byte[] extendedMasterSecretSessionHash =
                    spec.getExtendedMasterSecretSessionHash();
            if (extendedMasterSecretSessionHash.length != 0) {
                label = TlcpPrfGenerator.LABEL_EXTENDED_MASTER_SECRET;
                seed = extendedMasterSecretSessionHash;
            } else {
                byte[] clientRandom = spec.getClientRandom();
                byte[] serverRandom = spec.getServerRandom();
                label = TlcpPrfGenerator.LABEL_MASTER_SECRET;
                seed = TlcpPrfGenerator.concat(clientRandom, serverRandom);
            }
            master = TlcpPrfGenerator.doTLCPPRF(
                    premaster, label, seed, 48,
                    spec.getPRFHashAlg(), spec.getPRFHashLength(),
                    spec.getPRFBlockSize());
            return new TlcpMasterSecretKey(master, premasterMajor,
                    premasterMinor);
        } catch (NoSuchAlgorithmException | DigestException e) {
            throw new ProviderException(e);
        }
    }

    private static final class TlcpMasterSecretKey implements TlsMasterSecret {

        private static final long serialVersionUID = -6489330615790468561L;

        private final byte[] key;
        private final int majorVersion;
        private final int minorVersion;

        TlcpMasterSecretKey(byte[] key, int majorVersion, int minorVersion) {
            this.key = key;
            this.majorVersion = majorVersion;
            this.minorVersion = minorVersion;
        }

        public int getMajorVersion() {
            return majorVersion;
        }

        public int getMinorVersion() {
            return minorVersion;
        }

        public String getAlgorithm() {
            return "TlcpMasterSecret";
        }

        public String getFormat() {
            return "RAW";
        }

        public byte[] getEncoded() {
            return key.clone();
        }
    }
}
