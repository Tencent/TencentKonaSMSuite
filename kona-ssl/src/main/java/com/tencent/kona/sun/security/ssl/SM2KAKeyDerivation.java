/*
 * Copyright (c) 2022, 2023, Oracle and/or its affiliates. All rights reserved.
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

package com.tencent.kona.sun.security.ssl;

import com.tencent.kona.crypto.CryptoInsts;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;

final class SM2KAKeyDerivation implements SSLKeyDerivation {

    private final String algorithmName;
    private final HandshakeContext context;
    private final ECPrivateKey localEphemeralPrivateKey;
    private final ECPublicKey peerEphemeralPublicKey;

    SM2KAKeyDerivation(String algorithmName,
                       HandshakeContext context,
                       ECPrivateKey localEphemeralPrivateKey,
                       ECPublicKey peerEphemeralPublicKey) {
        this.algorithmName = algorithmName;
        this.context = context;
        this.localEphemeralPrivateKey = localEphemeralPrivateKey;
        this.peerEphemeralPublicKey = peerEphemeralPublicKey;
    }

    @Override
    public SecretKey deriveKey(String algorithm,
            AlgorithmParameterSpec params) throws IOException {
        try {
            KeyAgreement ka = CryptoInsts.getKeyAgreement(algorithmName);
            ka.init(localEphemeralPrivateKey, params, null);
            ka.doPhase(peerEphemeralPublicKey, true);
            SecretKey preMasterSecret = ka.generateSecret("TlsPremasterSecret");

            SSLMasterKeyDerivation mskd = SSLMasterKeyDerivation.valueOf(
                    context.negotiatedProtocol);
            if (mskd == null) {
                // unlikely
                throw new SSLHandshakeException(
                        "No expected master key derivation for protocol: " +
                        context.negotiatedProtocol.name);
            }
            SSLKeyDerivation kd = mskd.createKeyDerivation(
                    context, preMasterSecret);
            return kd.deriveKey("MasterSecret", params);
        } catch (GeneralSecurityException gse) {
            throw (SSLHandshakeException) new SSLHandshakeException(
                "Could not generate secret").initCause(gse);
        }
    }
}
