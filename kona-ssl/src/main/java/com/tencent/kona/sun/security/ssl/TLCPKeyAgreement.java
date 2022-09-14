package com.tencent.kona.sun.security.ssl;

import java.io.IOException;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Map;

enum TLCPKeyAgreement implements SSLKeyAgreement {

    SM2 ("sm2",  SM2KeyExchange.sm2PoGenerator,
                 SM2KeyExchange.sm2KAGenerator),
    SM2E("sm2e", SM2EKeyExchange.sm2ePoGenerator,
                 SM2EKeyExchange.sm2eKAGenerator);

    final String name;
    final SSLPossessionGenerator possessionGenerator;
    final SSLKeyAgreementGenerator keyAgreementGenerator;

    TLCPKeyAgreement(String name,
                     SSLPossessionGenerator possessionGenerator,
                     SSLKeyAgreementGenerator keyAgreementGenerator) {
        this.name = name;
        this.possessionGenerator = possessionGenerator;
        this.keyAgreementGenerator = keyAgreementGenerator;
    }

    @Override
    public SSLPossession createPossession(HandshakeContext context) {
        if (possessionGenerator != null) {
            return possessionGenerator.createPossession(context);
        }

        return null;
    }

    @Override
    public SSLKeyDerivation createKeyDerivation(
            HandshakeContext context) throws IOException {
        return keyAgreementGenerator.createKeyDerivation(context);
    }

    @Override
    public SSLHandshake[] getRelatedHandshakers(
            HandshakeContext handshakeContext) {
        if (!handshakeContext.negotiatedProtocol.useTLS13PlusSpec()) {
            if (this.possessionGenerator != null) {
                return new SSLHandshake[] {
                        SSLHandshake.SERVER_KEY_EXCHANGE
                };
            }
        }

        return new SSLHandshake[0];
    }

    @Override
    @SuppressWarnings({"unchecked", "rawtypes"})
    public Map.Entry<Byte, HandshakeProducer>[] getHandshakeProducers(
            HandshakeContext handshakeContext) {
        if (handshakeContext.negotiatedProtocol.useTLS13PlusSpec()) {
            return new Map.Entry[0];
        }

        if (handshakeContext.sslConfig.isClientMode) {
            switch (this) {
                case SM2:
                    return new Map.Entry[] {
                        new SimpleImmutableEntry<>(
                            SSLHandshake.CLIENT_KEY_EXCHANGE.id,
                            SM2ClientKeyExchange.sm2HandshakeProducer)};
                case SM2E:
                    return new Map.Entry[] {
                        new SimpleImmutableEntry<>(
                            SSLHandshake.CLIENT_KEY_EXCHANGE.id,
                            SM2EClientKeyExchange.sm2eHandshakeProducer)};
            }
        } else {
            switch (this) {
                case SM2:
                    return new Map.Entry[] {
                        new SimpleImmutableEntry<>(
                            SSLHandshake.SERVER_KEY_EXCHANGE.id,
                            SM2ServerKeyExchange.sm2HandshakeProducer)};
                case SM2E:
                    return new Map.Entry[] {
                        new SimpleImmutableEntry<>(
                            SSLHandshake.SERVER_KEY_EXCHANGE.id,
                            SM2EServerKeyExchange.sm2eHandshakeProducer)};
            }
        }

        return new Map.Entry[0];
    }

    @Override
    @SuppressWarnings({"unchecked", "rawtypes"})
    public Map.Entry<Byte, SSLConsumer>[] getHandshakeConsumers(
            HandshakeContext handshakeContext) {
        if (handshakeContext.negotiatedProtocol.useTLS13PlusSpec()) {
            return new Map.Entry[0];
        }

        if (handshakeContext.sslConfig.isClientMode) {
            switch (this) {
                case SM2:
                    return new Map.Entry[] {
                        new SimpleImmutableEntry<>(
                            SSLHandshake.SERVER_KEY_EXCHANGE.id,
                            SM2ServerKeyExchange.sm2HandshakeConsumer)};
                case SM2E:
                    return new Map.Entry[] {
                        new SimpleImmutableEntry<>(
                            SSLHandshake.SERVER_KEY_EXCHANGE.id,
                            SM2EServerKeyExchange.sm2eHandshakeConsumer)};
            }
        } else {
            switch (this) {
                case SM2:
                    return new Map.Entry[] {
                        new SimpleImmutableEntry<>(
                            SSLHandshake.CLIENT_KEY_EXCHANGE.id,
                            SM2ClientKeyExchange.sm2HandshakeConsumer)};
                case SM2E:
                    return new Map.Entry[] {
                        new SimpleImmutableEntry<>(
                            SSLHandshake.CLIENT_KEY_EXCHANGE.id,
                            SM2EClientKeyExchange.sm2eHandshakeConsumer)};
            }
        }

        return new Map.Entry[0];
    }
}
