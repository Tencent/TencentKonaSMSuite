/*
 * Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
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

package com.tencent.kona.crypto.spec;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * The parameters for SM2 key agreement.
 */
public class SM2KeyAgreementParamSpec implements AlgorithmParameterSpec {

    private static final byte[] DEFAULT_ID = "1234567812345678".getBytes();

    public final byte[] id;
    public final ECPrivateKey privateKey;
    public final ECPublicKey publicKey;

    public final byte[] peerId;
    public final ECPublicKey peerPublicKey;

    public final boolean isInitiator;

    // The length in bytes.
    public final int sharedKeyLength;

    public SM2KeyAgreementParamSpec(
            byte[] id, ECPrivateKey privateKey, ECPublicKey publicKey,
            byte[] peerId, ECPublicKey peerPublicKey,
            boolean isInitiator, int sharedKeyLength) {
        this.id = id.clone();
        this.privateKey = privateKey;
        this.publicKey = publicKey;

        this.peerId = peerId;
        this.peerPublicKey = peerPublicKey;

        this.isInitiator = isInitiator;
        this.sharedKeyLength = sharedKeyLength;
    }

    public SM2KeyAgreementParamSpec(
            ECPrivateKey privateKey, ECPublicKey publicKey,
            ECPublicKey peerPublicKey,
            boolean isInitiator, int sharedKeyLength) {
        this(DEFAULT_ID, privateKey, publicKey,
             DEFAULT_ID, peerPublicKey, isInitiator, sharedKeyLength);
    }
}
