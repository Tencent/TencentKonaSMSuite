/*
 * Copyright (C) 2022, 2024, Tencent. All rights reserved.
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
import com.tencent.kona.ssl.interop.CertTuple;
import com.tencent.kona.ssl.interop.CipherSuite;
import com.tencent.kona.ssl.interop.Client;
import com.tencent.kona.ssl.interop.ClientAuth;
import com.tencent.kona.ssl.interop.ContextProtocol;
import com.tencent.kona.ssl.interop.FileCert;
import com.tencent.kona.ssl.interop.JdkClient;
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
 * TLCP would not be restricted by the system properties on named groups
 * and signature schemes, since this protocol always work with only
 * curveSM2 and sm2sig_sm3.
 */
public class NoConstraintTest {

    @BeforeAll
    public static void setup() throws IOException {
        System.setProperty("com.tencent.kona.ssl.debug", "all");
        TestUtils.addProviders();
    }

    @Test
    public void testConnect() throws Exception {
        connect(TlcpUtils.CA_CERT,
                TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                TlcpUtils.INTCA_CERT,
                CipherSuite.TLCP_ECC_SM4_GCM_SM3,
                ClientAuth.REQUIRED);
    }

    private void connect(
            FileCert rootCA,
            FileCert serverSignCert, FileCert serverEncCert,
            FileCert clientSignCert, FileCert clientEncCert,
            FileCert intCA,
            CipherSuite clientCipherSuite,
            ClientAuth clientAuth) throws Exception {
        SmCertTuple serverCertTuple;
        if (intCA != null) {
            serverCertTuple = new SmCertTuple(
                    rootCA, serverSignCert, serverEncCert, intCA);
        } else {
            serverCertTuple = new SmCertTuple(
                    rootCA, serverSignCert, serverEncCert);
        }

        SmCertTuple clientCertTuple;
        if (intCA != null) {
            clientCertTuple = new SmCertTuple(
                    rootCA, clientSignCert, clientEncCert, intCA);
        } else {
            clientCertTuple = new SmCertTuple(
                    rootCA, clientSignCert, clientEncCert);
        }

        if (clientAuth != ClientAuth.REQUIRED
                // client must send certificates for TLCP_ECDHE cipher suites
                && !clientCipherSuite.name().startsWith("TLCP_ECDHE")) {
            clientCertTuple = new SmCertTuple(rootCA);
        }

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkProcServer.Builder serverBuilder = new JdkProcServer.Builder();
        serverBuilder.setContextProtocol(ContextProtocol.TLCP11);
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.setClientAuth(clientAuth);
        serverBuilder.addProp("com.tencent.kona.ssl.certListFormat", "SIGN|CA|ENC");
        serverBuilder.addProp("com.tencent.kona.ssl.namedGroups", "secp256r1");
        serverBuilder.addProp("com.tencent.kona.ssl.server.signatureSchemes", "ecdsa_secp256r1_sha256");
        serverBuilder.setMessage("Server");

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            try (Client client = createClientBuilder(
                    clientCertTuple, clientCipherSuite).build()) {
                client.connect("127.0.0.1", server.getPort());
            }
        } finally {
            executor.shutdown();
        }
    }

    private JdkClient.Builder createClientBuilder(CertTuple certTuple,
            CipherSuite cipherSuite) {
        JdkClient.Builder builder = new JdkClient.Builder();
        builder.setContextProtocol(ContextProtocol.TLCP11);
        builder.setCertTuple(certTuple);
        builder.setProtocols(Protocol.TLCPV1_1);
        builder.setCipherSuites(cipherSuite);
        builder.addProp("com.tencent.kona.ssl.namedGroups", "secp256r1");
        builder.addProp("com.tencent.kona.ssl.client.signatureSchemes", "ecdsa_secp256r1_sha256");
        builder.setMessage("Client");
        builder.setReadResponse(true);

        return builder;
    }
}
