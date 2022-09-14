package com.tencent.kona.crypto.spec;

import com.tencent.kona.crypto.provider.SM2PublicKey;
import com.tencent.kona.crypto.CryptoUtils;

import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

/**
 * The SM2 signature parameter specification.
 */
public class SM2SignatureParameterSpec implements AlgorithmParameterSpec {

    private byte[] id = CryptoUtils.toBytes("31323334353637383132333435363738");

    private final SM2PublicKey publicKey;

    public SM2SignatureParameterSpec(byte[] id, ECPublicKey publicKey) {
        Objects.requireNonNull(publicKey);

        if (id != null) {
            if (id.length >= 8192) {
                throw new IllegalArgumentException(
                        "The length of ID must be less than 8192-bytes");
            }

            this.id = id.clone();
        }

        this.publicKey = new SM2PublicKey(publicKey);
    }

    public SM2SignatureParameterSpec(ECPublicKey publicKey) {
        this(null, publicKey);
    }

    public byte[] getId() {
        return id.clone();
    }

    public ECPublicKey getPublicKey() {
        return publicKey;
    }
}
