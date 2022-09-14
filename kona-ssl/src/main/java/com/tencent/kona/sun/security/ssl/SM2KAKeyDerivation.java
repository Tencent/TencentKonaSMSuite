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
