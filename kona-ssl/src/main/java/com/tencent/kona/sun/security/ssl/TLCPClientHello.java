/*
 * Copyright (c) 2015, 2022, Oracle and/or its affiliates. All rights reserved.
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

import javax.net.ssl.SSLPeerUnverifiedException;
import java.io.IOException;
import java.util.Arrays;

final class TLCPClientHello {

    static final HandshakeConsumer tlcpHandshakeConsumer
            = new TLCPClientHelloConsumer();

    private static final class TLCPClientHelloConsumer
            implements HandshakeConsumer {

        // Prevent instantiation of this class.
        private TLCPClientHelloConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                            SSLHandshake.HandshakeMessage message) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;
            ClientHello.ClientHelloMessage clientHello = (ClientHello.ClientHelloMessage)message;

            //
            // validate
            //

            // Reject client initiated renegotiation?
            //
            // If server side should reject client-initiated renegotiation,
            // send an Alert.HANDSHAKE_FAILURE fatal alert, not a
            // no_renegotiation warning alert (no_renegotiation must be a
            // warning: RFC 2246).  no_renegotiation might seem more
            // natural at first, but warnings are not appropriate because
            // the sending party does not know how the receiving party
            // will behave.  This state must be treated as a fatal server
            // condition.
            //
            // This will not have any impact on server initiated renegotiation.
            if (shc.conContext.isNegotiated) {
                if (!shc.conContext.secureRenegotiation &&
                        !HandshakeContext.allowUnsafeRenegotiation) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "Unsafe renegotiation is not allowed");
                }

                if (ServerHandshakeContext.rejectClientInitiatedRenego &&
                        !shc.kickstartMessageDelivered) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "Client initiated renegotiation is not allowed");
                }
            }

            // Consume a Session Ticket Extension if it exists
            SSLExtension[] ext = new SSLExtension[]{
                    SSLExtension.CH_SESSION_TICKET
            };
            clientHello.extensions.consumeOnLoad(shc, ext);

            // Does the client want to resume a session?
            if (clientHello.sessionId.length() != 0 || shc.statelessResumption) {
                SSLSessionContextImpl cache = (SSLSessionContextImpl)shc.sslContext
                        .engineGetServerSessionContext();

                SSLSessionImpl previous;
                // Use the stateless session ticket if provided
                if (shc.statelessResumption) {
                    previous = shc.resumingSession;
                } else {
                    previous = cache.get(clientHello.sessionId.getId());
                }

                boolean resumingSession =
                        (previous != null) && previous.isRejoinable();
                if (!resumingSession) {
                    if (SSLLogger.isOn &&
                            SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest(
                                "Can't resume, " +
                                        "the existing session is not rejoinable");
                    }
                }
                // Validate the negotiated protocol version.
                if (resumingSession) {
                    ProtocolVersion sessionProtocol =
                            previous.getProtocolVersion();
                    if (sessionProtocol != shc.negotiatedProtocol) {
                        resumingSession = false;
                        if (SSLLogger.isOn &&
                                SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest(
                                    "Can't resume, not the same protocol version");
                        }
                    }
                }

                // Validate the required client authentication.
                if (resumingSession &&
                        (shc.sslConfig.clientAuthType == ClientAuthType.CLIENT_AUTH_REQUIRED)) {
                    try {
                        previous.getPeerPrincipal();
                    } catch (SSLPeerUnverifiedException e) {
                        resumingSession = false;
                        if (SSLLogger.isOn &&
                                SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest(
                                    "Can't resume, " +
                                            "client authentication is required");
                        }
                    }
                }

                // Validate that the cached cipher suite.
                if (resumingSession) {
                    CipherSuite suite = previous.getSuite();
                    if ((!shc.isNegotiable(suite)) ||
                            (!clientHello.cipherSuites.contains(suite))) {
                        resumingSession = false;
                        if (SSLLogger.isOn &&
                                SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest(
                                    "Can't resume, " +
                                            "the session cipher suite is absent");
                        }
                    }
                }

                // ensure that the endpoint identification algorithm matches the
                // one in the session
                String identityAlg = shc.sslConfig.identificationProtocol;
                if (resumingSession && identityAlg != null) {
                    String sessionIdentityAlg =
                            previous.getIdentificationProtocol();
                    if (!identityAlg.equalsIgnoreCase(sessionIdentityAlg)) {
                        if (SSLLogger.isOn &&
                                SSLLogger.isOn("ssl,handshake,verbose")) {
                            SSLLogger.finest("Can't resume, endpoint id" +
                                    " algorithm does not match, requested: " +
                                    identityAlg + ", cached: " + sessionIdentityAlg);
                        }
                        resumingSession = false;
                    }
                }

                // So far so good.  Note that the handshake extensions may reset
                // the resuming options later.
                shc.isResumption = resumingSession;
                shc.resumingSession = resumingSession ? previous : null;

                if (!resumingSession && SSLLogger.isOn &&
                        SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine("Session not resumed.");
                }
            }

            // cache the client random number for further using
            shc.clientHelloRandom = clientHello.clientRandom;

            // Check and launch ClientHello extensions.
            SSLExtension[] extTypes = shc.sslConfig.getExclusiveExtensions(
                    SSLHandshake.CLIENT_HELLO,
                    Arrays.asList(SSLExtension.CH_SESSION_TICKET));
            clientHello.extensions.consumeOnLoad(shc, extTypes);

            //
            // update
            //
            if (!shc.conContext.isNegotiated) {
                shc.conContext.protocolVersion = shc.negotiatedProtocol;
                shc.conContext.outputRecord.setVersion(shc.negotiatedProtocol);
            }

            // update the responders
            //
            // Only need to ServerHello, which may add more responders later.
            // Note that ServerHello and HelloRetryRequest share the same
            // handshake type/id.  The ServerHello producer may be replaced
            // by HelloRetryRequest producer if needed.
            shc.handshakeProducers.put(SSLHandshake.SERVER_HELLO.id,
                    SSLHandshake.SERVER_HELLO);

            //
            // produce
            //
            SSLHandshake[] probableHandshakeMessages = new SSLHandshake[] {
                    SSLHandshake.SERVER_HELLO,

                    // full handshake messages
                    SSLHandshake.CERTIFICATE,
                    SSLHandshake.CERTIFICATE_STATUS,
                    SSLHandshake.SERVER_KEY_EXCHANGE,
                    SSLHandshake.CERTIFICATE_REQUEST,
                    SSLHandshake.SERVER_HELLO_DONE,

                    // abbreviated handshake messages
                    SSLHandshake.FINISHED
            };

            for (SSLHandshake hs : probableHandshakeMessages) {
                HandshakeProducer handshakeProducer =
                        shc.handshakeProducers.remove(hs.id);
                if (handshakeProducer != null) {
                    handshakeProducer.produce(context, clientHello);
                }
            }
        }
    }
}
