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

package com.tencent.kona.ssl.tls;

import com.tencent.kona.ssl.TestUtils;
import com.tencent.kona.ssl.interop.CertTuple;
import com.tencent.kona.ssl.interop.CipherSuite;
import com.tencent.kona.ssl.interop.Client;
import com.tencent.kona.ssl.interop.ClientAuth;
import com.tencent.kona.ssl.interop.FileCert;
import com.tencent.kona.ssl.interop.HashAlgorithm;
import com.tencent.kona.ssl.interop.JdkClient;
import com.tencent.kona.ssl.interop.JdkProcClient;
import com.tencent.kona.ssl.interop.JdkServer;
import com.tencent.kona.ssl.interop.KeyAlgorithm;
import com.tencent.kona.ssl.interop.NamedGroup;
import com.tencent.kona.ssl.interop.Protocol;
import com.tencent.kona.ssl.interop.Provider;
import com.tencent.kona.ssl.interop.Server;
import com.tencent.kona.ssl.interop.ServerCaller;
import com.tencent.kona.ssl.interop.SignatureAlgorithm;
import com.tencent.kona.ssl.interop.SignatureScheme;
import com.tencent.kona.ssl.interop.Utilities;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The interop testing between SunJSSE server and Kona client.
 */
public class SunJSSEServerKonaClientTest {

    private static final FileCert ECDSA_INTCA_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256,
            "intca-p256ecdsa-p256ecdsa.crt",
            "intca-p256ecdsa-p256ecdsa.key");
    private static final FileCert ECDSA_EE_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256,
            "ee-p256ecdsa-p256ecdsa-p256ecdsa.crt",
            "ee-p256ecdsa-p256ecdsa-p256ecdsa.key");

    @BeforeAll
    public static void setup() throws IOException {
        TestUtils.addProviders();
    }

    @Test
    public void testConnWithECDSACertP256CurveOnTLS13() throws Exception {
        testConnWithECDSACertP256CurveOnTLS13(ClientAuth.NONE);
        testConnWithECDSACertP256CurveOnTLS13(ClientAuth.REQUIRED);
        testConnWithECDSACertP256CurveOnTLS13(ClientAuth.WANTED);
    }

    private void testConnWithECDSACertP256CurveOnTLS13(ClientAuth clientAuth)
            throws Exception {
        connect(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                clientAuth);
    }

    @Test
    public void testConnWithECDSACertP256CurveOnTLS12() throws Exception {
        testConnWithECDSACertP256CurveOnTLS12(ClientAuth.NONE);
        testConnWithECDSACertP256CurveOnTLS12(ClientAuth.REQUIRED);
        testConnWithECDSACertP256CurveOnTLS12(ClientAuth.WANTED);
    }

    private void testConnWithECDSACertP256CurveOnTLS12(ClientAuth clientAuth)
            throws Exception {
        connect(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_2,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                clientAuth);

        connect(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_2,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                clientAuth);
    }

    @Test
    // The server selects ECDSA_EE_CERT due to
    // the client prefers to ECDSA_SECP256R1_SHA256.
    public void testCertSelectionWithSigSchemeECDSAOnTLS13()
            throws Exception {
        connect(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                ClientAuth.NONE);
    }

    private void connect(
            FileCert[] trustedCerts,
            FileCert[] eeCerts,
            Protocol clientProtocol,
            CipherSuite clientCipherSuite,
            NamedGroup clientNamedGroup,
            SignatureScheme clientSignatureScheme,
            ClientAuth clientAuth) throws Exception {
        CertTuple serverCertTuple = new CertTuple(trustedCerts, eeCerts);
        CertTuple clientCertTuple = null;
        if (clientAuth == ClientAuth.REQUIRED) {
            clientCertTuple = new CertTuple(trustedCerts, eeCerts);
        } else {
            clientCertTuple = new CertTuple(trustedCerts, CertTuple.EMPTY);
        }

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkServer.Builder serverBuilder = new JdkServer.Builder();
        serverBuilder.setProvider(Provider.JDK);
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.setProtocols(Protocol.TLSV1_3, Protocol.TLSV1_2);
        serverBuilder.setCipherSuites(
                CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        serverBuilder.setClientAuth(clientAuth);
        serverBuilder.setMessage("Server");

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            JdkProcClient.Builder builder = new JdkProcClient.Builder();
            builder.setCertTuple(clientCertTuple);
            builder.setProtocols(clientProtocol);
            builder.setCipherSuites(clientCipherSuite);
            builder.setNamedGroups(clientNamedGroup);
            builder.setSignatureSchemes(clientSignatureScheme);
            builder.setMessage("Client");
            builder.setReadResponse(true);
            try (Client client = builder.build()) {
                client.connect("127.0.0.1", server.getPort());
            }
        } finally {
            executor.shutdown();
        }
    }

    @Test
    public void testResumptionWithECDSACertP256CurveOnTLS12() throws Exception {
        testResumptionWithECDSACertP256CurveOnTLS12(ClientAuth.NONE);
        testResumptionWithECDSACertP256CurveOnTLS12(ClientAuth.REQUIRED);
    }

    private void testResumptionWithECDSACertP256CurveOnTLS12(ClientAuth clientAuth)
            throws Exception {
        resumeSession(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_2,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                clientAuth);

        resumeSession(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_2,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                clientAuth);
    }

    private void resumeSession(
            FileCert[] trustedCerts,
            FileCert[] eeCerts,
            Protocol clientProtocol,
            CipherSuite clientCipherSuite,
            ClientAuth clientAuth) throws Exception {
        CertTuple certTuple = new CertTuple(trustedCerts, eeCerts);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkServer.Builder serverBuilder = new JdkServer.Builder();
        serverBuilder.setProvider(Provider.JDK);
        serverBuilder.setCertTuple(certTuple);
        serverBuilder.setProtocols(Protocol.TLSV1_3, Protocol.TLSV1_2);
        serverBuilder.setCipherSuites(
                CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        serverBuilder.setClientAuth(clientAuth);

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            SSLContext context = null;
            long firstCreationTime = 0;
            try (JdkClient client = createResumedClient(
                    certTuple, clientProtocol, clientCipherSuite,
                    null)) {
                client.connect("127.0.0.1", server.getPort());
                context = client.context;
                firstCreationTime = client.getSession().getCreationTime();
            }

            try (JdkClient client = createResumedClient(
                    certTuple, clientProtocol, clientCipherSuite,
                    context)) {
                client.connect("127.0.0.1", server.getPort());

                long secondCreationTime = client.getSession().getCreationTime();
                Assertions.assertEquals(firstCreationTime, secondCreationTime);
            }
        } finally {
            executor.shutdown();
        }
    }

    private JdkClient createResumedClient(
            CertTuple certTuple, Protocol protocol, CipherSuite cipherSuite,
            SSLContext context) throws Exception {
        JdkClient.Builder builder = new JdkClient.Builder();
        builder.setCertTuple(certTuple);
        builder.setProtocols(protocol);
        builder.setCipherSuites(cipherSuite);
        builder.setMessage("Client");
        builder.setReadResponse(true);
        builder.setContext(context);
        return builder.build();
    }
}
