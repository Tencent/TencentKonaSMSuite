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

import com.tencent.kona.ssl.interop.BabaSSLClient;
import com.tencent.kona.ssl.interop.CertTuple;
import com.tencent.kona.ssl.interop.CipherSuite;
import com.tencent.kona.ssl.interop.Client;
import com.tencent.kona.ssl.interop.ClientAuth;
import com.tencent.kona.ssl.interop.ContextProtocol;
import com.tencent.kona.ssl.interop.FileCert;
import com.tencent.kona.ssl.interop.JdkServer;
import com.tencent.kona.ssl.interop.Protocol;
import com.tencent.kona.ssl.interop.Server;
import com.tencent.kona.ssl.interop.ServerCaller;
import com.tencent.kona.ssl.interop.SmCertTuple;
import com.tencent.kona.ssl.interop.Utilities;
import com.tencent.kona.ssl.TestUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The interop test between JDK server and BabaSSL(OpenSSL) client.
 */
public class JdkServerBabaSSLClient {

    private static final String SESS_FILE_NAME = "babassl.sess";

    @BeforeAll
    public static void setup() throws IOException {
        TestUtils.addProviders();
    }

    @AfterAll
    public static void clean() throws IOException {
        deleteSessFile();
    }

    private static void deleteSessFile() throws IOException {
        Files.deleteIfExists(Paths.get(SESS_FILE_NAME));
    }

    @Test
    public void testConnect() throws Exception {
        testConnect(ClientAuth.NONE);
        testConnectWithSingleCert(ClientAuth.NONE);
    }

    @Test
    public void testConnectWithClientAuth() throws Exception {
        testConnect(ClientAuth.REQUIRED);
        testConnectWithSingleCert(ClientAuth.REQUIRED);
    }

    private void testConnect(ClientAuth clientAuth) throws Exception {
        connect(TlcpUtils.INTCA_CERT,
                TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                clientAuth);
        connect(TlcpUtils.INTCA_CERT,
                TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                CipherSuite.TLCP_ECC_SM4_GCM_SM3,
                clientAuth);
    }

    private void testConnectWithSingleCert(ClientAuth clientAuth) throws Exception {
        connect(TlcpUtils.INTCA_CERT,
                TlcpUtils.SERVER_CERT, null,
                TlcpUtils.CLIENT_CERT, null,
                CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                clientAuth);
        connect(TlcpUtils.INTCA_CERT,
                TlcpUtils.SERVER_CERT, null,
                TlcpUtils.CLIENT_CERT, null,
                CipherSuite.TLCP_ECC_SM4_GCM_SM3,
                clientAuth);
    }

    // When use ECDHE_ cipher suites,
    // the server requires client's certificates implicitly.
    @Test
    public void testConnectOnEphemeral() throws Exception {
        connect(TlcpUtils.INTCA_CERT,
                TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                CipherSuite.TLCP_ECDHE_SM4_CBC_SM3,
                ClientAuth.NONE);
        connect(TlcpUtils.INTCA_CERT,
                TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                CipherSuite.TLCP_ECDHE_SM4_GCM_SM3,
                ClientAuth.NONE);
    }

    private void connect(
            FileCert trustedCert,
            FileCert serverSignCert, FileCert serverEncCert,
            FileCert clientSignCert, FileCert clientEncCert,
            CipherSuite clientCipherSuite,
            ClientAuth clientAuth) throws Exception {
        SmCertTuple serverCertTuple = new SmCertTuple(
                trustedCert, serverSignCert, serverEncCert);
        SmCertTuple clientCertTuple = new SmCertTuple(
                trustedCert, clientSignCert, clientEncCert);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkServer.Builder serverBuilder = new JdkServer.Builder();
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.setContextProtocol(ContextProtocol.TLCP11);
        serverBuilder.setClientAuth(clientAuth);

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            BabaSSLClient.Builder clientBuilder = new BabaSSLClient.Builder();
            clientBuilder.setCertTuple(clientCertTuple);
            clientBuilder.setProtocols(Protocol.TLCPV1_1);
            clientBuilder.setCipherSuites(clientCipherSuite);
            clientBuilder.setMessage("Q");  // quit s_client
            clientBuilder.setReadResponse(false);

            try (Client client = clientBuilder.build()) {
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
                TlcpUtils.INTCA_CERT, TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT);
        SmCertTuple clientCertTuple = new SmCertTuple(
                TlcpUtils.INTCA_CERT, TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkServer.Builder serverBuilder = new JdkServer.Builder();
        serverBuilder.setContextProtocol(ContextProtocol.TLCP11);
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.setAppProtocols("HTTP/1.1", "h2");
        serverBuilder.setClientAuth(clientAuth);

        try (JdkServer server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            BabaSSLClient.Builder clientBuilder = createClientBuilder(
                    clientCertTuple, clientCipherSuite);
            clientBuilder.setAppProtocols("h2");
            try (BabaSSLClient client = clientBuilder.build()) {
                client.connect("127.0.0.1", server.getPort());
                Assertions.assertEquals("h2", server.getNegoAppProtocol());
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
                TlcpUtils.INTCA_CERT, TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT);
        SmCertTuple clientCertTuple = new SmCertTuple(
                TlcpUtils.INTCA_CERT, TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkServer.Builder serverBuilder = new JdkServer.Builder();
        serverBuilder.setContextProtocol(ContextProtocol.TLCP11);
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.setServerNames("www.example.com");
        serverBuilder.setClientAuth(clientAuth);
        serverBuilder.setMessage("Server");

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            BabaSSLClient.Builder clientBuilder = createClientBuilder(
                    clientCertTuple, clientCipherSuite);
            clientBuilder.setServerNames("www.example.com");
            try (BabaSSLClient client = clientBuilder.build()) {
                client.connect("127.0.0.1", server.getPort());
            }
        } finally {
            executor.shutdown();
        }
    }

    @Test
    public void testResumption() throws Exception {
        testResumption(false, ClientAuth.NONE);
        testResumption(true, ClientAuth.NONE);
    }

    @Test
    public void testResumptionWithClientAuth() throws Exception {
        testResumption(false, ClientAuth.REQUIRED);
        testResumption(true, ClientAuth.REQUIRED);
    }

    private void testResumption(boolean useSessTicket, ClientAuth clientAuth)
            throws Exception {
        resumeSession(TlcpUtils.INTCA_CERT,
                TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                useSessTicket,
                clientAuth);
        resumeSession(TlcpUtils.INTCA_CERT,
                TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                CipherSuite.TLCP_ECC_SM4_GCM_SM3,
                useSessTicket,
                clientAuth);
    }

    private void resumeSession(
            FileCert trustedCert,
            FileCert serverSignCert, FileCert serverEncCert,
            FileCert clientSignCert, FileCert clientEncCert,
            CipherSuite clientCipherSuite,
            boolean useSessionTicket,
            ClientAuth clientAuth) throws Exception {
        SmCertTuple serverCertTuple = new SmCertTuple(
                trustedCert, serverSignCert, serverEncCert);
        SmCertTuple clientCertTuple = new SmCertTuple(
                trustedCert, clientSignCert, clientEncCert);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkServer.Builder serverBuilder = new JdkServer.Builder();
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.setContextProtocol(ContextProtocol.TLCP11);
        serverBuilder.setClientAuth(clientAuth);

        try (JdkServer server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            long firstCreationTime = 0;
            try (BabaSSLClient client = createClientBuilder(
                    clientCertTuple, clientCipherSuite,
                    useSessionTicket,
                    SESS_FILE_NAME, true).build()) {
                client.connect("127.0.0.1", server.getPort());
                firstCreationTime = server.getSession().getCreationTime();
            }

            try (BabaSSLClient client = createClientBuilder(
                    clientCertTuple, clientCipherSuite,
                    useSessionTicket,
                    SESS_FILE_NAME, false).build()) {
                client.connect("127.0.0.1", server.getPort());

                long secondCreationTime = server.getSession().getCreationTime();
                Assertions.assertEquals(firstCreationTime, secondCreationTime);
            }
        } finally {
            executor.shutdown();
        }
    }

    private BabaSSLClient.Builder createClientBuilder(CertTuple certTuple,
                                                      CipherSuite cipherSuite, boolean useSessionTicket,
                                                      String sessFile, boolean saveSess) {
        BabaSSLClient.Builder builder = new BabaSSLClient.Builder();
        builder.setCertTuple(certTuple);
        builder.setProtocols(Protocol.TLCPV1_1);
        builder.setCipherSuites(cipherSuite);
        builder.setMessage("Q");  // quit s_client
        builder.setReadResponse(false);
        builder.setUseSessTicket(useSessionTicket);

        if (sessFile != null) {
            if (saveSess) {
                builder.sessOut(sessFile);
            } else {
                builder.sessIn(sessFile);
            }
        }

        return builder;
    }

    private BabaSSLClient.Builder createClientBuilder(CertTuple certTuple,
            CipherSuite cipherSuite) {
        return createClientBuilder(certTuple, cipherSuite, false, null, false);
    }
}
