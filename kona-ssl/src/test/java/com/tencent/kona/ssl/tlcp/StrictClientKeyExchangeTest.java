/*
 * Copyright (C) 2026, Tencent. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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
 */

package com.tencent.kona.ssl.tlcp;

import com.tencent.kona.ssl.TestUtils;
import com.tencent.kona.ssl.interop.CipherSuite;
import com.tencent.kona.ssl.interop.Client;
import com.tencent.kona.ssl.interop.ClientAuth;
import com.tencent.kona.ssl.interop.ContextProtocol;
import com.tencent.kona.ssl.interop.JdkProcClient;
import com.tencent.kona.ssl.interop.JdkProcServer;
import com.tencent.kona.ssl.interop.Protocol;
import com.tencent.kona.ssl.interop.Server;
import com.tencent.kona.ssl.interop.ServerCaller;
import com.tencent.kona.ssl.interop.SmCertTuple;
import com.tencent.kona.ssl.interop.Utilities;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Interop coverage for the GB/T 38636-2020 compliant TLCP ephemeral SM2
 * (ECDHE_SM2) ClientKeyExchange framing gated by the system property
 * {@code com.tencent.kona.ssl.tlcp.strictClientKeyExchange}.
 *
 * The property only controls how the client emits ClientECDHEParams.  The
 * server always accepts both framings.  All four combinations of
 * client-side and server-side strict/legacy configuration must therefore
 * complete the handshake successfully across both TLCP ECDHE cipher
 * suites.  Each combination runs client and server in their own JVMs so
 * that the property is applied at the earliest possible point (before
 * SM2EClientKeyExchange class initialization).
 */
public class StrictClientKeyExchangeTest {

    private static final String STRICT_CKE_PROP
            = "com.tencent.kona.ssl.tlcp.strictClientKeyExchange";

    private static final CipherSuite[] ECDHE_SUITES = {
            CipherSuite.TLCP_ECDHE_SM4_CBC_SM3,
            CipherSuite.TLCP_ECDHE_SM4_GCM_SM3,
    };

    @BeforeAll
    public static void setup() throws IOException {
        TestUtils.addProviders();
    }

    // Critical direction: strict client (GB/T 38636-2020 framed) talks to
    // a server left on the historical Kona defaults.  A successful
    // handshake proves the parser accepts a u16-length-prefixed
    // ClientECDHEParams via the peek-0x00 branch.
    @Test
    public void testStrictClientLegacyServer() throws Exception {
        for (CipherSuite suite : ECDHE_SUITES) {
            connect(suite, true, false);
        }
    }

    // Reverse direction: legacy-emitting client to a server whose
    // strictClientKeyExchange property is on.  The property is a
    // sender-only knob, so the parser must still accept the bare
    // legacy framing via the peek-0x03 branch.
    @Test
    public void testLegacyClientStrictServer() throws Exception {
        for (CipherSuite suite : ECDHE_SUITES) {
            connect(suite, false, true);
        }
    }

    // Both peers speak strict framing end to end.
    @Test
    public void testStrictClientStrictServer() throws Exception {
        for (CipherSuite suite : ECDHE_SUITES) {
            connect(suite, true, true);
        }
    }

    // Baseline: default behavior, matches the existing TLCP tests.
    @Test
    public void testLegacyClientLegacyServer() throws Exception {
        for (CipherSuite suite : ECDHE_SUITES) {
            connect(suite, false, false);
        }
    }

    private void connect(CipherSuite cipherSuite,
                         boolean clientStrict,
                         boolean serverStrict) throws Exception {
        // ECDHE cipher suites require client certificates.
        SmCertTuple serverCertTuple = new SmCertTuple(
                TlcpUtils.CA_CERT,
                TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                TlcpUtils.INTCA_CERT);
        SmCertTuple clientCertTuple = new SmCertTuple(
                TlcpUtils.CA_CERT,
                TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                TlcpUtils.INTCA_CERT);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkProcServer.Builder serverBuilder = new JdkProcServer.Builder();
        serverBuilder.setContextProtocol(ContextProtocol.TLCP11);
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.setClientAuth(ClientAuth.REQUIRED);
        serverBuilder.setMessage("Server");
        serverBuilder.addProp(STRICT_CKE_PROP, Boolean.toString(serverStrict));

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            JdkProcClient.Builder clientBuilder = new JdkProcClient.Builder();
            clientBuilder.setContextProtocol(ContextProtocol.TLCP11);
            clientBuilder.setCertTuple(clientCertTuple);
            clientBuilder.setProtocols(Protocol.TLCPV1_1);
            clientBuilder.setCipherSuites(cipherSuite);
            clientBuilder.setMessage("Client");
            clientBuilder.setReadResponse(true);
            clientBuilder.addProp(STRICT_CKE_PROP, Boolean.toString(clientStrict));

            try (Client client = clientBuilder.build()) {
                client.connect("127.0.0.1", server.getPort());
            }
        } finally {
            executor.shutdown();
        }
    }
}
