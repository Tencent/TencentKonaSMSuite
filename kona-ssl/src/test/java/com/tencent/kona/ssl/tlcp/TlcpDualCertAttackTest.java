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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Handshake-level coverage of the report's primary attack payload against the
 * real TLCP server consume path (Certificate parse -> createCredentials ->
 * strict pair check -> CertificateVerify binding).
 *
 * <p>The malicious client presents a cross-subject, dual-keyUsage certificate
 * list — slot0 {@code CN=tlcp-client} (dual KU), slot1 {@code CN=tlcp-server}
 * (dual KU) — the shape of {@code [victim-enc-k2, attacker-k2]} from the
 * vulnerability report, where the session identity would be taken from slot0.
 *
 * <p>Client and server run in their own JVMs so the per-process compat flag
 * can differ. The client is always in compat mode so it will actually emit the
 * dual-KU pair (a strict producer would refuse to build it). Only the server's
 * {@code tlcpDualCertCompat} flag varies between the two cases, so the
 * different outcome isolates the server's strict createCredentials check as the
 * cause of rejection.
 */
public class TlcpDualCertAttackTest {

    private static final String COMPAT_PROP
            = "com.tencent.kona.ssl.tlcpDualCertCompat";

    @BeforeAll
    public static void setup() throws IOException {
        TestUtils.addProviders();
    }

    // Default strict server: the cross-subject dual-KU client list is rejected
    // in createCredentials, so the forked client handshake fails.
    @Test
    public void attackListRejectedByStrictServer() {
        Assertions.assertThrows(IOException.class, () -> connect(false));
    }

    // Legacy compat server: the same list restores the old (vulnerable)
    // behavior and the handshake completes.
    @Test
    public void attackListAcceptedByCompatServer() throws Exception {
        connect(true);
    }

    private void connect(boolean serverCompat) throws Exception {
        SmCertTuple serverCertTuple = new SmCertTuple(
                TlcpUtils.CA_CERT,
                TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                TlcpUtils.INTCA_CERT);
        // Malicious client list: two dual-KU certificates with different
        // subjects (slot0 CN=tlcp-client, slot1 CN=tlcp-server).
        SmCertTuple clientCertTuple = new SmCertTuple(
                TlcpUtils.CA_CERT,
                TlcpUtils.CLIENT_CERT, TlcpUtils.SERVER_CERT,
                TlcpUtils.INTCA_CERT);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkProcServer.Builder serverBuilder = new JdkProcServer.Builder();
        serverBuilder.setContextProtocol(ContextProtocol.TLCP11);
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.setClientAuth(ClientAuth.REQUIRED);
        serverBuilder.setMessage("Server");
        serverBuilder.addProp(COMPAT_PROP, Boolean.toString(serverCompat));

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            JdkProcClient.Builder clientBuilder = new JdkProcClient.Builder();
            clientBuilder.setContextProtocol(ContextProtocol.TLCP11);
            clientBuilder.setCertTuple(clientCertTuple);
            clientBuilder.setProtocols(Protocol.TLCPV1_1);
            clientBuilder.setCipherSuites(CipherSuite.TLCP_ECDHE_SM4_CBC_SM3);
            clientBuilder.setMessage("Client");
            clientBuilder.setReadResponse(true);
            // Always compat so the client actually emits the dual-KU pair.
            clientBuilder.addProp(COMPAT_PROP, "true");

            try (Client client = clientBuilder.build()) {
                client.connect("127.0.0.1", server.getPort());
            }
        } finally {
            executor.shutdown();
        }
    }
}
