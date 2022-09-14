package com.tencent.kona.crypto.spec;

import com.tencent.kona.crypto.provider.SM2PrivateKey;
import com.tencent.kona.crypto.provider.SM2PublicKey;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import static com.tencent.kona.crypto.util.Constants.defaultId;

/**
 * The parameters for SM2 key agreement.
 */
public class SM2KeyAgreementParamSpec implements AlgorithmParameterSpec {

    public final byte[] id;
    public final SM2PrivateKey privateKey;
    public final SM2PublicKey publicKey;

    public final byte[] peerId;
    public final SM2PublicKey peerPublicKey;

    public final boolean isInitiator;

    // The length in bytes.
    public final int sharedKeyLength;

    public SM2KeyAgreementParamSpec(
            byte[] id, ECPrivateKey privateKey, ECPublicKey publicKey,
            byte[] peerId, ECPublicKey peerPublicKey,
            boolean isInitiator, int sharedKeyLength) {
        this.id = id;
        this.privateKey = new SM2PrivateKey(privateKey);
        this.publicKey = new SM2PublicKey(publicKey);

        this.peerId = peerId;
        this.peerPublicKey = new SM2PublicKey(peerPublicKey);

        this.isInitiator = isInitiator;
        this.sharedKeyLength = sharedKeyLength;
    }

    public SM2KeyAgreementParamSpec(
            ECPrivateKey privateKey, ECPublicKey publicKey,
            ECPublicKey peerPublicKey,
            boolean isInitiator, int sharedKeyLength) {
        this(defaultId(), privateKey, publicKey,
                defaultId(), peerPublicKey, isInitiator, sharedKeyLength);
    }
}
