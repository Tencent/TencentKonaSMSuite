/*
 * Copyright (C) 2022, 2023, Tencent. All rights reserved.
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

package com.tencent.kona.ssl.hybrid;

import com.tencent.kona.ssl.interop.Cert;
import com.tencent.kona.ssl.interop.CertTuple;
import com.tencent.kona.ssl.interop.CipherSuite;
import com.tencent.kona.ssl.interop.Client;
import com.tencent.kona.ssl.interop.ClientAuth;
import com.tencent.kona.ssl.interop.ContextProtocol;
import com.tencent.kona.ssl.interop.JdkClient;
import com.tencent.kona.ssl.interop.JdkProcClient;
import com.tencent.kona.ssl.interop.JdkProcServer;
import com.tencent.kona.ssl.interop.JdkServer;
import com.tencent.kona.ssl.interop.Protocol;
import com.tencent.kona.ssl.interop.SSLTestException;
import com.tencent.kona.ssl.interop.Server;
import com.tencent.kona.ssl.interop.ServerCaller;
import com.tencent.kona.ssl.interop.Utilities;
import com.tencent.kona.ssl.SSLUtils;
import com.tencent.kona.ssl.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The interop test between JDK server and client.
 * The peers support different protocols and cipher suites.
 */
public class JdkServerJdkClientTest {

    @BeforeAll
    public static void setup() throws IOException {
        SSLUtils.setPropCertListFormat("SIGN|CA|ENC");
        TestUtils.addProviders();
    }

    @Test
    public void testProtocolDeterminedByServer() throws Exception {
        testProtocolDeterminedByServer(ClientAuth.NONE);
    }

    @Test
    public void testProtocolDeterminedByServerWithClientAuth() throws Exception {
        testProtocolDeterminedByServer(ClientAuth.REQUIRED);
    }

    private void testProtocolDeterminedByServer(ClientAuth clientAuth)
            throws Exception {
        testConnect(
                new Protocol[]{Protocol.TLCPV1_1},
                new Protocol[]{Protocol.TLSV1_3, Protocol.TLSV1_2, Protocol.TLCPV1_1},
                clientAuth);
        testConnect(
                new Protocol[]{Protocol.TLSV1_2},
                new Protocol[]{Protocol.TLSV1_3, Protocol.TLSV1_2, Protocol.TLCPV1_1},
                clientAuth);
        testConnect(
                new Protocol[]{Protocol.TLSV1_3},
                new Protocol[]{Protocol.TLSV1_3, Protocol.TLSV1_2, Protocol.TLCPV1_1},
                clientAuth);
    }

    @Test
    public void testProtocolDeterminedByClient() throws Exception {
        testProtocolDeterminedByClient(ClientAuth.NONE);
    }

    @Test
    public void testProtocolDeterminedByClientWithClientAuth() throws Exception {
        testProtocolDeterminedByClient(ClientAuth.REQUIRED);
    }

    private void testProtocolDeterminedByClient(ClientAuth clientAuth)
            throws Exception {
        testConnect(
                new Protocol[] {Protocol.TLSV1_3, Protocol.TLSV1_2, Protocol.TLCPV1_1},
                new Protocol[] {Protocol.TLCPV1_1},
                clientAuth);
        testConnect(
                new Protocol[] {Protocol.TLSV1_3, Protocol.TLSV1_2, Protocol.TLCPV1_1},
                new Protocol[] {Protocol.TLSV1_2},
                clientAuth);
        testConnect(
                new Protocol[] {Protocol.TLSV1_3, Protocol.TLSV1_2, Protocol.TLCPV1_1},
                new Protocol[] {Protocol.TLSV1_3},
                clientAuth);
    }

    private void testConnect(
            Protocol[] serverProtocols,
            Protocol[] clientProtocols,
            ClientAuth clientAuth) throws Exception {
        connect(
                new Cert[] { HybridUtils.EC_SERVER, HybridUtils.RSA_SERVER, HybridUtils.SM_SERVER_SIGN, HybridUtils.SM_SERVER_ENC },
                new Cert[] { HybridUtils.EC_CLIENT, HybridUtils.RSA_CLIENT, HybridUtils.SM_CLIENT_SIGN, HybridUtils.SM_CLIENT_ENC },
                serverProtocols,
                clientProtocols,
                new CipherSuite[] {
                        CipherSuite.TLS_AES_128_GCM_SHA256,
                        CipherSuite.TLS_SM4_GCM_SM3,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                        CipherSuite.TLCP_ECDHE_SM4_CBC_SM3 },
                new CipherSuite[] {
                        CipherSuite.TLS_SM4_GCM_SM3,
                        CipherSuite.TLS_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                        CipherSuite.TLCP_ECDHE_SM4_CBC_SM3 },
                clientAuth);
    }

    private void connect(
            Cert[] serverCerts,
            Cert[] clientCerts,
            Protocol[] serverProtocols,
            Protocol[] clientProtocols,
            CipherSuite[] serverCipherSuites,
            CipherSuite[] clientCipherSuites,
            ClientAuth clientAuth) throws Exception {
        CertTuple serverCertTuple = new CertTuple(
                new Cert[] { HybridUtils.RSA_INTCA, HybridUtils.EC_INTCA, HybridUtils.SM_INTCA },
                serverCerts);
        CertTuple clientCertTuple = new CertTuple(
                new Cert[] { HybridUtils.RSA_INTCA, HybridUtils.EC_INTCA, HybridUtils.SM_INTCA },
                clientCerts);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkServer.Builder serverBuilder = new JdkServer.Builder();
        serverBuilder.setContextProtocol(ContextProtocol.TLCP);
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.setProtocols(serverProtocols);
        serverBuilder.setCipherSuites(serverCipherSuites);
        serverBuilder.setClientAuth(clientAuth);
        serverBuilder.addProp("com.tencent.kona.ssl.certListFormat", "SIGN|CA|ENC");
        serverBuilder.setMessage("Server");

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            try (Client client = createClientBuilder(
                    clientCertTuple, clientProtocols, clientCipherSuites)
                    .build()) {
                client.connect("127.0.0.1", server.getPort());
            }
        } finally {
            executor.shutdown();
        }
    }

    private JdkClient.Builder createClientBuilder(
            CertTuple certTuple,
            Protocol[] protocols,
            CipherSuite[] cipherSuites,
            SSLContext context) {
        JdkClient.Builder builder = new JdkClient.Builder();
        builder.setContextProtocol(ContextProtocol.TLCP);
        builder.setCertTuple(certTuple);
        builder.setProtocols(protocols);
        builder.setCipherSuites(cipherSuites);
        builder.setMessage("Client");
        builder.setReadResponse(true);
        builder.setContext(context);

        return builder;
    }

    private JdkClient.Builder createClientBuilder(
            CertTuple certTuple,
            Protocol[] protocols,
            CipherSuite[] cipherSuites) {
        return createClientBuilder(certTuple, protocols, cipherSuites, null);
    }

    @Test
    public void testProtocolDeterminedWithProtocolProps() throws Exception {
        testConnectWithProtocolProps(
                "TLSv1.3,TLSv1.2,TLCPv1.1",
                "TLCPv1.1",
                ClientAuth.NONE);
        testConnectWithProtocolProps(
                "TLSv1.3,TLSv1.2,TLCPv1.1",
                "TLSv1.2",
                ClientAuth.NONE);
        testConnectWithProtocolProps(
                "TLSv1.3,TLSv1.2,TLCPv1.1",
                "TLSv1.3",
                ClientAuth.NONE);

        // No protocol can be negotiated
        Assertions.assertThrows(SSLTestException.class,
                () -> testConnectWithProtocolProps(
                        "TLSv1.3",
                        "TLCPv1.1",
                        ClientAuth.NONE));
    }

    private void testConnectWithProtocolProps(
            String serverProtocols,
            String clientProtocols,
            ClientAuth clientAuth) throws Exception {
        connectWithProtocolProps(
                new Cert[] { HybridUtils.EC_SERVER, HybridUtils.RSA_SERVER, HybridUtils.SM_SERVER_SIGN, HybridUtils.SM_SERVER_ENC },
                new Cert[] { HybridUtils.EC_CLIENT, HybridUtils.RSA_CLIENT, HybridUtils.SM_CLIENT_SIGN, HybridUtils.SM_CLIENT_ENC },
                serverProtocols,
                clientProtocols,
                new CipherSuite[] {
                        CipherSuite.TLS_AES_128_GCM_SHA256,
                        CipherSuite.TLS_SM4_GCM_SM3,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                        CipherSuite.TLCP_ECDHE_SM4_CBC_SM3 },
                new CipherSuite[] {
                        CipherSuite.TLS_SM4_GCM_SM3,
                        CipherSuite.TLS_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                        CipherSuite.TLCP_ECDHE_SM4_CBC_SM3 },
                clientAuth);
    }

    private void connectWithProtocolProps(
            Cert[] serverCerts,
            Cert[] clientCerts,
            String serverProtocols,
            String clientProtocols,
            CipherSuite[] serverCipherSuites,
            CipherSuite[] clientCipherSuites,
            ClientAuth clientAuth) throws Exception {
        CertTuple serverCertTuple = new CertTuple(
                new Cert[] { HybridUtils.RSA_INTCA, HybridUtils.EC_INTCA, HybridUtils.SM_INTCA },
                serverCerts);
        CertTuple clientCertTuple = new CertTuple(
                new Cert[] { HybridUtils.RSA_INTCA, HybridUtils.EC_INTCA, HybridUtils.SM_INTCA },
                clientCerts);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkProcServer.Builder serverBuilder = new JdkProcServer.Builder();
        serverBuilder.setContextProtocol(ContextProtocol.TLCP);
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.addProp("com.tencent.kona.ssl.server.protocols", serverProtocols);
        serverBuilder.setCipherSuites(serverCipherSuites);
        serverBuilder.setClientAuth(clientAuth);
        serverBuilder.addProp("com.tencent.kona.ssl.certListFormat", "SIGN|CA|ENC");
        serverBuilder.setMessage("Server");

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            try (Client client = createClientBuilderWithProtocolProp(
                    clientCertTuple, clientProtocols, clientCipherSuites)
                    .build()) {
                client.connect("127.0.0.1", server.getPort());
            }
        } finally {
            executor.shutdown();
        }
    }

    private JdkProcClient.Builder createClientBuilderWithProtocolProp(
            CertTuple certTuple,
            String protocols,
            CipherSuite[] cipherSuites) {
        JdkProcClient.Builder builder = new JdkProcClient.Builder();
        builder.setContextProtocol(ContextProtocol.TLCP);
        builder.setCertTuple(certTuple);
        builder.addProp("com.tencent.kona.ssl.client.protocols", protocols);
        builder.setCipherSuites(cipherSuites);
        builder.setMessage("Client");
        builder.setReadResponse(true);

        return builder;
    }
}
