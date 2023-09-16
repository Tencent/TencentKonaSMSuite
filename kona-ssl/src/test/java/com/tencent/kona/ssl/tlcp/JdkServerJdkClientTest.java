/*
 * Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
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
import com.tencent.kona.ssl.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The interop test between JDK server and client.
 */
public class JdkServerJdkClientTest {

    @BeforeAll
    public static void setup() throws IOException {
        TestUtils.addProviders();
    }

    @Test
    public void testConnect() throws Exception {
        testConnect(ClientAuth.NONE);
    }

    @Test
    public void testConnectWithClientAuth() throws Exception {
        testConnect(ClientAuth.REQUIRED);
        testConnect(ClientAuth.WANTED);
    }

    private void testConnect(ClientAuth clientAuth) throws Exception {
        connect(TlcpUtils.CA_CERT,
                TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                TlcpUtils.INTCA_CERT,
                CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                clientAuth);
        connect(TlcpUtils.CA_CERT,
                TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                TlcpUtils.INTCA_CERT,
                CipherSuite.TLCP_ECC_SM4_GCM_SM3,
                clientAuth);
    }

    @Test
    public void testConnectWithSingleCert() throws Exception {
        testConnectWithSingleCert(ClientAuth.NONE);
    }

    @Test
    public void testConnectWithSingleCertAndClientAuth() throws Exception {
        testConnectWithSingleCert(ClientAuth.REQUIRED);
    }

    private void testConnectWithSingleCert(ClientAuth clientAuth) throws Exception {
        connect(TlcpUtils.CA_CERT,
                TlcpUtils.SERVER_CERT, null,
                TlcpUtils.CLIENT_CERT, null,
                TlcpUtils.INTCA_CERT,
                CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                clientAuth);
        connect(TlcpUtils.CA_CERT,
                TlcpUtils.SERVER_CERT, null,
                TlcpUtils.CLIENT_CERT, null,
                TlcpUtils.INTCA_CERT,
                CipherSuite.TLCP_ECC_SM4_GCM_SM3,
                clientAuth);
    }

    @Test
    public void testFailedConnect() {
        // No enc cert
        TestUtils.checkThrowable(SSLException.class,
                () -> connect(
                        TlcpUtils.CA_CERT,
                        TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_SIGN_CERT,
                        TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                        TlcpUtils.INTCA_CERT,
                        CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                        ClientAuth.NONE));

        // No sign cert
        TestUtils.checkThrowable(SSLException.class,
                () -> connect(
                        TlcpUtils.CA_CERT,
                        TlcpUtils.SERVER_ENC_CERT, TlcpUtils.SERVER_ENC_CERT,
                        TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                        TlcpUtils.INTCA_CERT,
                        CipherSuite.TLCP_ECC_SM4_GCM_SM3,
                        ClientAuth.NONE));
    }

    // When use ECDHE_ cipher suites,
    // the server always requires client's certificates.
    @Test
    public void testConnectOnEphemeral() throws Exception {
        connect(TlcpUtils.CA_CERT,
                TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                TlcpUtils.INTCA_CERT,
                CipherSuite.TLCP_ECDHE_SM4_CBC_SM3,
                ClientAuth.NONE);
        connect(TlcpUtils.CA_CERT,
                TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                TlcpUtils.INTCA_CERT,
                CipherSuite.TLCP_ECDHE_SM4_GCM_SM3,
                ClientAuth.NONE);
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

    @Test
    public void testALPN() throws Exception {
        testALPN(CipherSuite.TLCP_ECC_SM4_CBC_SM3, ClientAuth.NONE);
        testALPN(CipherSuite.TLCP_ECC_SM4_CBC_SM3, ClientAuth.REQUIRED);
        testALPN(CipherSuite.TLCP_ECC_SM4_GCM_SM3, ClientAuth.NONE);
        testALPN(CipherSuite.TLCP_ECC_SM4_GCM_SM3, ClientAuth.REQUIRED);
    }

    private void testALPN(CipherSuite clientCipherSuite, ClientAuth clientAuth)
            throws Exception {
        SmCertTuple serverCertTuple = new SmCertTuple(
                TlcpUtils.INTCA_CERT, TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT, TlcpUtils.INTCA_CERT);
        SmCertTuple clientCertTuple = new SmCertTuple(
                TlcpUtils.INTCA_CERT, TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT, TlcpUtils.INTCA_CERT);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkProcServer.Builder serverBuilder = new JdkProcServer.Builder();
        serverBuilder.setContextProtocol(ContextProtocol.TLCP11);
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.setAppProtocols("HTTP/1.1", "h2");
        serverBuilder.setClientAuth(clientAuth);
        serverBuilder.setMessage("Server");

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            JdkClient.Builder clientBuilder = createClientBuilder(
                    clientCertTuple, clientCipherSuite);
            clientBuilder.setAppProtocols("h2");
            try (JdkClient client = clientBuilder.build()) {
                client.connect("127.0.0.1", server.getPort());
                Assertions.assertEquals("h2", client.getNegoAppProtocol());
            }
        } finally {
            executor.shutdown();
        }
    }

    @Test
    public void testSNI() throws Exception {
        testSNI(CipherSuite.TLCP_ECC_SM4_CBC_SM3, ClientAuth.NONE);
        testSNI(CipherSuite.TLCP_ECC_SM4_CBC_SM3, ClientAuth.REQUIRED);
        testSNI(CipherSuite.TLCP_ECC_SM4_GCM_SM3, ClientAuth.NONE);
        testSNI(CipherSuite.TLCP_ECC_SM4_GCM_SM3, ClientAuth.REQUIRED);
    }

    private void testSNI(CipherSuite clientCipherSuite, ClientAuth clientAuth)
            throws Exception {
        SmCertTuple serverCertTuple = new SmCertTuple(
                TlcpUtils.INTCA_CERT, TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT, TlcpUtils.INTCA_CERT);
        SmCertTuple clientCertTuple = new SmCertTuple(
                TlcpUtils.INTCA_CERT, TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT, TlcpUtils.INTCA_CERT);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkProcServer.Builder serverBuilder = new JdkProcServer.Builder();
        serverBuilder.setContextProtocol(ContextProtocol.TLCP11);
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.setServerNames("www.example.com");
        serverBuilder.setClientAuth(clientAuth);
        serverBuilder.setMessage("Server");

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            JdkClient.Builder clientBuilder = createClientBuilder(
                    clientCertTuple, clientCipherSuite);
            clientBuilder.setServerNames("www.example.com");
            try (JdkClient client = clientBuilder.build()) {
                client.connect("127.0.0.1", server.getPort());
            }
        } finally {
            executor.shutdown();
        }
    }

    @Test
    public void testResumption() throws Exception {
        testResumption(ClientAuth.NONE);
        testResumption(ClientAuth.REQUIRED);
    }

    private void testResumption(ClientAuth clientAuth) throws Exception {
        resumeSession(
                TlcpUtils.INTCA_CERT,
                TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                TlcpUtils.INTCA_CERT,
                CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                clientAuth);
        resumeSession(
                TlcpUtils.INTCA_CERT,
                TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                TlcpUtils.INTCA_CERT,
                CipherSuite.TLCP_ECC_SM4_GCM_SM3,
                clientAuth);
    }

    private void resumeSession(
            FileCert rootCA,
            FileCert serverSignCert, FileCert serverEncCert,
            FileCert clientSignCert, FileCert clientEncCert,
            FileCert intCA,
            CipherSuite clientCipherSuite,
            ClientAuth clientAuth) throws Exception {
        SmCertTuple serverCertTuple = new SmCertTuple(
                rootCA, serverSignCert, serverEncCert, intCA);
        SmCertTuple clientCertTuple = new SmCertTuple(
                rootCA, clientSignCert, clientEncCert, intCA);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkProcServer.Builder serverBuilder = new JdkProcServer.Builder();
        serverBuilder.setContextProtocol(ContextProtocol.TLCP11);
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.setClientAuth(clientAuth);
        serverBuilder.setMessage("Server");

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            SSLContext context = null;
            long firstCreationTime = 0;
            try (JdkClient client = createClientBuilder(
                    clientCertTuple, clientCipherSuite).build()) {
                client.connect("127.0.0.1", server.getPort());
                context = client.context;
                firstCreationTime = client.getSession().getCreationTime();
            }

            try (JdkClient client = createClientBuilder(
                    clientCertTuple, clientCipherSuite,
                    context).build()) {
                client.connect("127.0.0.1", server.getPort());

                long secondCreationTime = client.getSession().getCreationTime();
                Assertions.assertEquals(firstCreationTime, secondCreationTime);
            }
        } finally {
            executor.shutdown();
        }
    }

    private JdkClient.Builder createClientBuilder(CertTuple certTuple,
            CipherSuite cipherSuite, SSLContext context) {
        JdkClient.Builder builder = new JdkClient.Builder();
        builder.setContextProtocol(ContextProtocol.TLCP11);
        builder.setCertTuple(certTuple);
        builder.setProtocols(Protocol.TLCPV1_1);
        builder.setCipherSuites(cipherSuite);
        builder.setMessage("Client");
        builder.setReadResponse(true);
        builder.setContext(context);

        return builder;
    }

    private JdkClient.Builder createClientBuilder(
            CertTuple certTuple, CipherSuite cipherSuite) {
        return createClientBuilder(certTuple, cipherSuite, null);
    }
}
