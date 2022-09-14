package com.tencent.kona.sun.security.ssl;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

final class TLCPServerHello {

    static final HandshakeProducer tlcpHandshakeProducer
            = new TLCPServerHelloProducer();

    static final HandshakeConsumer tlcpHandshakeConsumer
            = new TLCPServerHelloConsumer();

    private static final class TLCPServerHelloProducer
            implements HandshakeProducer {

        // Prevent instantiation of this class.
        private TLCPServerHelloProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                              SSLHandshake.HandshakeMessage message) throws IOException {
            // The producing happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;
            ClientHello.ClientHelloMessage clientHello = (ClientHello.ClientHelloMessage)message;

            // If client hasn't specified a session we can resume, start a
            // new one and choose its cipher suite and compression options,
            // unless new session creation is disabled for this connection!
            if (!shc.isResumption || shc.resumingSession == null) {
                if (!shc.sslConfig.enableSessionCreation) {
                    throw new SSLException(
                            "Not resumption, and no new session is allowed");
                }

                if (shc.localSupportedSignAlgs == null) {
                    shc.localSupportedSignAlgs =
                            SignatureScheme.getSupportedAlgorithms(
                                    shc.sslConfig,
                                    shc.algorithmConstraints, shc.activeProtocols);
                }

                SSLSessionImpl session =
                        new SSLSessionImpl(shc, CipherSuite.C_NULL);
                session.setMaximumPacketSize(shc.sslConfig.maximumPacketSize);
                shc.handshakeSession = session;

                // consider the handshake extension impact
                SSLExtension[] enabledExtensions =
                        shc.sslConfig.getEnabledExtensions(
                                SSLHandshake.CLIENT_HELLO, shc.negotiatedProtocol);
                clientHello.extensions.consumeOnTrade(shc, enabledExtensions);

                // negotiate the cipher suite.
                KeyExchangeProperties credentials =
                        chooseCipherSuite(shc, clientHello);
                if (credentials == null) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "no cipher suites in common");
                }
                shc.negotiatedCipherSuite = credentials.cipherSuite;
                shc.handshakeKeyExchange = credentials.keyExchange;
                shc.handshakeSession.setSuite(credentials.cipherSuite);
                shc.handshakePossessions.addAll(
                        Arrays.asList(credentials.possessions));
                shc.handshakeHash.determine(
                        shc.negotiatedProtocol, shc.negotiatedCipherSuite);

                // Check the incoming OCSP stapling extensions and attempt
                // to get responses.  If the resulting stapleParams is non
                // null, it implies that stapling is enabled on the server side.
                shc.stapleParams = StatusResponseManager.processStapling(shc);
                shc.staplingActive = (shc.stapleParams != null);

                // update the responders
                SSLKeyExchange ke = credentials.keyExchange;
                if (ke != null) {
                    for (Map.Entry<Byte, HandshakeProducer> me :
                            ke.getHandshakeProducers(shc)) {
                        shc.handshakeProducers.put(
                                me.getKey(), me.getValue());
                    }
                }

                if ((ke != null)
                        && (shc.sslConfig.clientAuthType != ClientAuthType.CLIENT_AUTH_NONE
                                // TLCP ECDHE cipher suites must require client's certificates
                                || shc.negotiatedCipherSuite == CipherSuite.TLCP_ECDHE_SM4_GCM_SM3
                                || shc.negotiatedCipherSuite == CipherSuite.TLCP_ECDHE_SM4_CBC_SM3)
                        && !shc.negotiatedCipherSuite.isAnonymous()) {
                    for (SSLHandshake hs :
                            ke.getRelatedHandshakers(shc)) {
                        if (hs == SSLHandshake.CERTIFICATE) {
                            shc.handshakeProducers.put(
                                    SSLHandshake.CERTIFICATE_REQUEST.id,
                                    SSLHandshake.CERTIFICATE_REQUEST);
                            break;
                        }
                    }
                }
                shc.handshakeProducers.put(SSLHandshake.SERVER_HELLO_DONE.id,
                        SSLHandshake.SERVER_HELLO_DONE);
            } else {
                // stateless and use the client session id (RFC 5077 3.4)
                if (shc.statelessResumption) {
                    shc.resumingSession = new SSLSessionImpl(shc.resumingSession,
                            (clientHello.sessionId.length() == 0) ?
                                    new SessionId(true,
                                            shc.sslContext.getSecureRandom()) :
                                    new SessionId(clientHello.sessionId.getId())
                    );
                }
                shc.handshakeSession = shc.resumingSession;
                shc.negotiatedProtocol =
                        shc.resumingSession.getProtocolVersion();
                shc.negotiatedCipherSuite = shc.resumingSession.getSuite();
                shc.handshakeHash.determine(
                        shc.negotiatedProtocol, shc.negotiatedCipherSuite);
            }

            // Generate the ServerHello handshake message.
            ServerHello.ServerHelloMessage shm = new ServerHello.ServerHelloMessage(shc,
                    shc.negotiatedProtocol,
                    shc.handshakeSession.getSessionId(),
                    shc.negotiatedCipherSuite,
                    new RandomCookie(shc),
                    clientHello);
            shc.serverHelloRandom = shm.serverRandom;

            // Produce extensions for ServerHello handshake message.
            SSLExtension[] serverHelloExtensions =
                    shc.sslConfig.getEnabledExtensions(
                            SSLHandshake.SERVER_HELLO, shc.negotiatedProtocol);
            shm.extensions.produce(shc, serverHelloExtensions);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced ServerHello handshake message", shm);
            }

            // Output the handshake message.
            shm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();

            if (shc.isResumption && shc.resumingSession != null) {
                SSLTrafficKeyDerivation kdg =
                        SSLTrafficKeyDerivation.valueOf(shc.negotiatedProtocol);
                if (kdg == null) {
                    // unlikely
                    throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                            "Not supported key derivation: " +
                                    shc.negotiatedProtocol);
                } else {
                    shc.handshakeKeyDerivation = kdg.createKeyDerivation(
                            shc, shc.resumingSession.getMasterSecret());
                }

                // update the responders
                shc.handshakeProducers.put(SSLHandshake.FINISHED.id,
                        SSLHandshake.FINISHED);
            }

            // The handshake message has been delivered.
            return null;
        }

        private static KeyExchangeProperties chooseCipherSuite(
                ServerHandshakeContext shc,
                ClientHello.ClientHelloMessage clientHello) throws IOException {
            List<CipherSuite> preferred;
            List<CipherSuite> proposed;
            if (shc.sslConfig.preferLocalCipherSuites) {
                preferred = shc.activeCipherSuites;
                proposed = clientHello.cipherSuites;
            } else {
                preferred = clientHello.cipherSuites;
                proposed = shc.activeCipherSuites;
            }

            for (CipherSuite cs : preferred) {
                if (!HandshakeContext.isNegotiable(
                        proposed, shc.negotiatedProtocol, cs)) {
                    continue;
                }

                if (shc.sslConfig.clientAuthType ==
                        ClientAuthType.CLIENT_AUTH_REQUIRED) {
                    if ((cs.keyExchange == CipherSuite.KeyExchange.K_DH_ANON) ||
                            (cs.keyExchange == CipherSuite.KeyExchange.K_ECDH_ANON)) {
                        continue;
                    }
                }

                SSLKeyExchange ke = SSLKeyExchange.valueOf(
                        cs.keyExchange, shc.negotiatedProtocol);
                if (ke == null) {
                    continue;
                }

                SSLPossession[] hcds = ke.createPossessions(shc);
                if ((hcds == null) || (hcds.length == 0)) {
                    continue;
                }

                // The cipher suite has been negotiated.
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("use cipher suite " + cs.name);
                }

                return new KeyExchangeProperties(cs, ke, hcds);
            }

            throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                    "no cipher suites in common");
        }

        private static final class KeyExchangeProperties {
            final CipherSuite cipherSuite;
            final SSLKeyExchange keyExchange;
            final SSLPossession[] possessions;

            private KeyExchangeProperties(CipherSuite cipherSuite,
                                          SSLKeyExchange keyExchange, SSLPossession[] possessions) {
                this.cipherSuite = cipherSuite;
                this.keyExchange = keyExchange;
                this.possessions = possessions;
            }
        }
    }

    private static final class TLCPServerHelloConsumer implements HandshakeConsumer {
        // Prevent instantiation of this class.
        private TLCPServerHelloConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                            SSLHandshake.HandshakeMessage message) throws IOException {
            // The consuming happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;
            ServerHello.ServerHelloMessage serverHello = (ServerHello.ServerHelloMessage)message;
            if (!chc.isNegotiable(serverHello.serverVersion)) {
                throw chc.conContext.fatal(Alert.PROTOCOL_VERSION,
                        "Server chose " + serverHello.serverVersion +
                                ", but that protocol version is not enabled or " +
                                "not supported by the client.");
            }

            // chc.negotiatedProtocol = serverHello.serverVersion;
            chc.negotiatedCipherSuite = serverHello.cipherSuite;
            chc.handshakeHash.determine(
                    chc.negotiatedProtocol, chc.negotiatedCipherSuite);
            chc.serverHelloRandom = serverHello.serverRandom;
            if (chc.negotiatedCipherSuite.keyExchange == null) {
                throw chc.conContext.fatal(Alert.PROTOCOL_VERSION,
                        "TLCP does not support the server cipher suite: "
                                + chc.negotiatedCipherSuite.name);
            }

            //
            // validate
            //

            // Check and launch the "renegotiation_info" extension.
            SSLExtension[] extTypes = new SSLExtension[] {
                    SSLExtension.SH_RENEGOTIATION_INFO
            };
            serverHello.extensions.consumeOnLoad(chc, extTypes);

            // Is it session resuming?
            if (chc.resumingSession != null) {
                // we tried to resume, let's see what the server decided
                if (serverHello.sessionId.equals(
                        chc.resumingSession.getSessionId())) {
                    // server resumed the session, let's make sure everything
                    // checks out

                    // Verify that the session ciphers are unchanged.
                    CipherSuite sessionSuite = chc.resumingSession.getSuite();
                    if (chc.negotiatedCipherSuite != sessionSuite) {
                        throw chc.conContext.fatal(Alert.PROTOCOL_VERSION,
                                "Server returned wrong cipher suite for session");
                    }

                    // verify protocol version match
                    ProtocolVersion sessionVersion =
                            chc.resumingSession.getProtocolVersion();
                    if (chc.negotiatedProtocol != sessionVersion) {
                        throw chc.conContext.fatal(Alert.PROTOCOL_VERSION,
                                "Server resumed with wrong protocol version");
                    }

                    // looks fine;  resume it.
                    chc.isResumption = true;
                    chc.resumingSession.setAsSessionResumption(true);
                    chc.handshakeSession = chc.resumingSession;
                } else {
                    // we wanted to resume, but the server refused
                    //
                    // Invalidate the session for initial handshake in case
                    // of reusing next time.
                    if (chc.resumingSession != null) {
                        chc.resumingSession.invalidate();
                        chc.resumingSession = null;
                    }
                    chc.isResumption = false;
                    if (!chc.sslConfig.enableSessionCreation) {
                        throw chc.conContext.fatal(Alert.PROTOCOL_VERSION,
                                "New session creation is disabled");
                    }
                }
            }

            // Check and launch ClientHello extensions.
            extTypes = chc.sslConfig.getEnabledExtensions(
                    SSLHandshake.SERVER_HELLO);
            serverHello.extensions.consumeOnLoad(chc, extTypes);

            if (!chc.isResumption) {
                if (chc.resumingSession != null) {
                    // in case the resumption happens next time.
                    chc.resumingSession.invalidate();
                    chc.resumingSession = null;
                }

                if (!chc.sslConfig.enableSessionCreation) {
                    throw chc.conContext.fatal(Alert.PROTOCOL_VERSION,
                            "New session creation is disabled");
                }

                if (serverHello.sessionId.length() == 0 &&
                        chc.statelessResumption) {
                    SessionId newId = new SessionId(true,
                            chc.sslContext.getSecureRandom());
                    chc.handshakeSession = new SSLSessionImpl(chc,
                            chc.negotiatedCipherSuite, newId);

                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.fine("Locally assigned Session Id: " +
                                newId.toString());
                    }
                } else {
                    chc.handshakeSession = new SSLSessionImpl(chc,
                            chc.negotiatedCipherSuite,
                            serverHello.sessionId);
                }
                chc.handshakeSession.setMaximumPacketSize(
                        chc.sslConfig.maximumPacketSize);
            }

            //
            // update
            //
            serverHello.extensions.consumeOnTrade(chc, extTypes);

            // update the consumers and producers
            if (chc.isResumption) {
                SSLTrafficKeyDerivation kdg =
                        SSLTrafficKeyDerivation.valueOf(chc.negotiatedProtocol);
                if (kdg == null) {
                    // unlikely
                    throw chc.conContext.fatal(Alert.INTERNAL_ERROR,
                            "Not supported key derivation: " +
                                    chc.negotiatedProtocol);
                } else {
                    chc.handshakeKeyDerivation = kdg.createKeyDerivation(
                            chc, chc.resumingSession.getMasterSecret());
                }

                if (chc.statelessResumption) {
                    chc.handshakeConsumers.putIfAbsent(
                            SSLHandshake.NEW_SESSION_TICKET.id,
                            SSLHandshake.NEW_SESSION_TICKET);
                }
                chc.conContext.consumers.putIfAbsent(
                        ContentType.CHANGE_CIPHER_SPEC.id,
                        TLCPChangeCipherSpec.tlcpConsumer);
                chc.handshakeConsumers.put(
                        SSLHandshake.FINISHED.id,
                        SSLHandshake.FINISHED);
            } else {
                SSLKeyExchange ke = SSLKeyExchange.valueOf(
                        chc.negotiatedCipherSuite.keyExchange,
                        chc.negotiatedProtocol);
                chc.handshakeKeyExchange = ke;
                if (ke != null) {
                    for (SSLHandshake handshake :
                            ke.getRelatedHandshakers(chc)) {
                        chc.handshakeConsumers.put(handshake.id, handshake);
                    }
                }

                chc.handshakeConsumers.put(SSLHandshake.SERVER_HELLO_DONE.id,
                        SSLHandshake.SERVER_HELLO_DONE);
            }

            //
            // produce
            //
            // Need no new handshake message producers here.
        }
    }
}
