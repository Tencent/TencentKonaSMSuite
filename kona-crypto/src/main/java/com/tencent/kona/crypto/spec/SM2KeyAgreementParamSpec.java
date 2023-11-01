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

import com.tencent.kona.crypto.CryptoUtils;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

/**
 * The parameters used by SM2 key agreement.
 */
public final class SM2KeyAgreementParamSpec implements AlgorithmParameterSpec {

    // The default ID 1234567812345678
    private static final byte[] DEFAULT_ID = new byte[] {
            49, 50, 51, 52, 53, 54, 55, 56,
            49, 50, 51, 52, 53, 54, 55, 56};

    private final byte[] id;
    private final ECPrivateKey privateKey;
    private final ECPublicKey publicKey;

    private final byte[] peerId;
    private final ECPublicKey peerPublicKey;

    private final boolean isInitiator;

    // The length in bytes.
    private final int sharedKeyLength;

    /**
     * Create a new {@code SM2KeyAgreementParamSpec}.
     *
     * @param id the ID.
     * @param privateKey the private key.
     * @param publicKey the public key.
     * @param peerId the peer's ID.
     * @param peerPublicKey the peer's public key.
     * @param isInitiator true indicates it initiates the key exchanging;
     *                    false indicates peer initiates the key exchange.
     * @param sharedKeyLength the length of the shared key.
     *
     * @exception NullPointerException any parameter is null.
     */
    public SM2KeyAgreementParamSpec(
            byte[] id, ECPrivateKey privateKey, ECPublicKey publicKey,
            byte[] peerId, ECPublicKey peerPublicKey,
            boolean isInitiator, int sharedKeyLength) {
        Objects.requireNonNull(id, "id must not null");
        Objects.requireNonNull(privateKey, "privateKey must not null");
        Objects.requireNonNull(publicKey, "publicKey must not null");
        Objects.requireNonNull(peerId, "peerId must not null");
        Objects.requireNonNull(peerPublicKey, "peerPublicKey must not null");

        CryptoUtils.checkId(id);
        CryptoUtils.checkId(peerId);

        this.id = id.clone();
        this.privateKey = privateKey;
        this.publicKey = publicKey;

        this.peerId = peerId.clone();
        this.peerPublicKey = peerPublicKey;

        this.isInitiator = isInitiator;
        this.sharedKeyLength = sharedKeyLength;
    }

    /**
     * Create a new {@code SM2KeyAgreementParamSpec}.
     * It just uses the default ID, exactly {@code 1234567812345678}.
     *
     * @param privateKey the private key.
     * @param publicKey the public key.
     * @param peerPublicKey the peer's public key.
     * @param isInitiator true indicates it initiates the key exchanging;
     *                    false indicates peer initiates the key exchange.
     * @param sharedKeyLength the length of the shared key.
     *
     * @exception NullPointerException any parameter is null.
     */
    public SM2KeyAgreementParamSpec(
            ECPrivateKey privateKey, ECPublicKey publicKey,
            ECPublicKey peerPublicKey,
            boolean isInitiator, int sharedKeyLength) {
        this(DEFAULT_ID, privateKey, publicKey,
             DEFAULT_ID, peerPublicKey, isInitiator, sharedKeyLength);
    }

    public byte[] id() {
        return id.clone();
    }

    public ECPrivateKey privateKey() {
        return privateKey;
    }

    public ECPublicKey publicKey() {
        return publicKey;
    }

    public byte[] peerId() {
        return peerId.clone();
    }

    public ECPublicKey peerPublicKey() {
        return peerPublicKey;
    }

    public boolean isInitiator() {
        return isInitiator;
    }

    public int sharedKeyLength() {
        return sharedKeyLength;
    }
}
