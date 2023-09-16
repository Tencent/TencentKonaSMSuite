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

import com.tencent.kona.ssl.interop.CertTuple;
import com.tencent.kona.ssl.interop.CipherSuite;
import com.tencent.kona.ssl.interop.Client;
import com.tencent.kona.ssl.interop.ClientAuth;
import com.tencent.kona.ssl.interop.FileCert;
import com.tencent.kona.ssl.interop.HashAlgorithm;
import com.tencent.kona.ssl.interop.JdkClient;
import com.tencent.kona.ssl.interop.JdkProcClient;
import com.tencent.kona.ssl.interop.KeyAlgorithm;
import com.tencent.kona.ssl.interop.NamedGroup;
import com.tencent.kona.ssl.interop.OpenSSLServer;
import com.tencent.kona.ssl.interop.Protocol;
import com.tencent.kona.ssl.interop.Server;
import com.tencent.kona.ssl.interop.ServerCaller;
import com.tencent.kona.ssl.interop.SignatureAlgorithm;
import com.tencent.kona.ssl.interop.SignatureScheme;
import com.tencent.kona.ssl.interop.Utilities;
import com.tencent.kona.ssl.TestUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The interop testing between BabaSSL(OpenSSL) server and JDK client.
 */
public class BabaSSLServerJdkClientTest {

    private static final FileCert ECDSA_INTCA_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256,
            "intca-p256ecdsa-p256ecdsa.crt",
            "intca-p256ecdsa-p256ecdsa.key");
    private static final FileCert ECDSA_EE_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256,
            "ee-p256ecdsa-p256ecdsa-p256ecdsa.crt",
            "ee-p256ecdsa-p256ecdsa-p256ecdsa.key");

    private static final FileCert SM_INTCA_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "intca-sm2sm2-sm2sm2.crt",
            "intca-sm2sm2-sm2sm2.key");
    private static final FileCert SM_EE_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "ee-sm2sm2-sm2sm2-sm2sm2.crt",
            "ee-sm2sm2-sm2sm2-sm2sm2.key");

    private static final String PAGE_FILE_NAME = "page";

    @BeforeAll
    public static void setup() throws IOException {
        TestUtils.addProviders();
        createWebPage();
    }

    private static void createWebPage() throws IOException {
        Files.write(Paths.get(PAGE_FILE_NAME),
                "OpenSSL server".getBytes(Utilities.CHARSET),
                StandardOpenOption.CREATE);
    }

    @AfterAll
    public static void clean() throws IOException {
        deleteWebPage();
    }

    private static void deleteWebPage() throws IOException {
        Files.deleteIfExists(Paths.get(PAGE_FILE_NAME));
    }

    @Test
    public void testConnWithECDSACertP256CurveOnTLS13() throws Exception {
        testConnWithECDSACertP256CurveOnTLS13(ClientAuth.NONE);
        testConnWithECDSACertP256CurveOnTLS13(ClientAuth.REQUIRED);
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

        connect(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_SM4_GCM_SM3,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                clientAuth);
    }

    @Test
    public void testConnWithECDSACertSM2CurveOnTLS13() throws Exception {
        testConnWithECDSACertSM2CurveOnTLS13(ClientAuth.NONE);
        testConnWithECDSACertSM2CurveOnTLS13(ClientAuth.REQUIRED);
    }

    private void testConnWithECDSACertSM2CurveOnTLS13(ClientAuth clientAuth)
            throws Exception {
        connect(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.CURVESM2,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                clientAuth);

        connect(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_SM4_GCM_SM3,
                NamedGroup.CURVESM2,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                clientAuth);
    }

    @Test
    public void testConnWithECDSACertP256CurveOnTLS12() throws Exception {
        testConnWithECDSACertP256CurveOnTLS12(ClientAuth.NONE);
        testConnWithECDSACertP256CurveOnTLS12(ClientAuth.REQUIRED);
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
    public void testConnWithSM2CertP256CurveOnTLS13() throws Exception {
        testConnWithSM2CertP256CurveOnTLS13(ClientAuth.NONE);
        testConnWithSM2CertP256CurveOnTLS13(ClientAuth.REQUIRED);
    }

    private void testConnWithSM2CertP256CurveOnTLS13(ClientAuth clientAuth)
            throws Exception {
        connect(
                new FileCert[] { SM_INTCA_CERT },
                new FileCert[] { SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.SM2SIG_SM3,
                clientAuth);

        connect(
                new FileCert[] { SM_INTCA_CERT },
                new FileCert[] { SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_SM4_GCM_SM3,
                NamedGroup.SECP256R1,
                SignatureScheme.SM2SIG_SM3,
                clientAuth);
    }

    @Test
    public void testConnWithSM2CertSM2CurveOnTLS13() throws Exception {
        testConnWithSM2CertSM2CurveOnTLS13(ClientAuth.NONE);
        testConnWithSM2CertSM2CurveOnTLS13(ClientAuth.REQUIRED);
    }

    private void testConnWithSM2CertSM2CurveOnTLS13(ClientAuth clientAuth)
            throws Exception {
        connect(
                new FileCert[] { SM_INTCA_CERT },
                new FileCert[] { SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.CURVESM2,
                SignatureScheme.SM2SIG_SM3,
                clientAuth);

        connect(
                new FileCert[] { SM_INTCA_CERT },
                new FileCert[] { SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_SM4_GCM_SM3,
                NamedGroup.CURVESM2,
                SignatureScheme.SM2SIG_SM3,
                clientAuth);
    }

    private void connect(
            FileCert[] trustedCerts,
            FileCert[] eeCerts,
            Protocol clientProtocol,
            CipherSuite clientCipherSuite,
            NamedGroup clientNamedGroup,
            SignatureScheme signatureScheme,
            ClientAuth clientAuth) throws Exception {
        CertTuple certTuple = new CertTuple(trustedCerts, eeCerts);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        OpenSSLServer.Builder serverBuilder = new OpenSSLServer.Builder();
        serverBuilder.setCertTuple(certTuple);
        serverBuilder.setProtocols(Protocol.TLSV1_3, Protocol.TLSV1_2);
        serverBuilder.setCipherSuites(
                CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_SM4_GCM_SM3,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        serverBuilder.setClientAuth(clientAuth);

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            try (Client client = createProcClient(
                    certTuple, clientProtocol,
                    clientCipherSuite, clientNamedGroup,
                    signatureScheme)) {
                client.connect("127.0.0.1", server.getPort());
            }
        } finally {
            executor.shutdown();
        }
    }

    private JdkProcClient createProcClient(
            CertTuple certTuple, Protocol protocol,
            CipherSuite cipherSuite, NamedGroup namedGroup,
            SignatureScheme signatureScheme) throws Exception {
        JdkProcClient.Builder builder = new JdkProcClient.Builder();
        builder.setCertTuple(certTuple);
        builder.setProtocols(protocol);
        builder.setCipherSuites(cipherSuite);
        builder.setNamedGroups(namedGroup);
        builder.setSignatureSchemes(signatureScheme);
        builder.setMessage(
                // An HTTP request asks to access the page.
                String.format("GET /%s HTTP/1.1\r\n", PAGE_FILE_NAME));
        builder.setReadResponse(true);
        return builder.build();
    }

    @Test
    public void testResumptionWithECDSACertP256CurveOnTLS13() throws Exception {
        testResumptionWithECDSACertP256CurveOnTLS13(ClientAuth.NONE);
        testResumptionWithECDSACertP256CurveOnTLS13(ClientAuth.REQUIRED);
    }

    private void testResumptionWithECDSACertP256CurveOnTLS13(ClientAuth clientAuth)
            throws Exception {
        resumeSession(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                true,
                clientAuth);

        resumeSession(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_SM4_GCM_SM3,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                true,
                clientAuth);
    }

    @Test
    public void testResumptionWithSM2CertSM2CurveOnTLS13() throws Exception {
        testResumptionWithSM2CertSM2CurveOnTLS13(ClientAuth.NONE);
        testResumptionWithSM2CertSM2CurveOnTLS13(ClientAuth.REQUIRED);
    }

    private void testResumptionWithSM2CertSM2CurveOnTLS13(ClientAuth clientAuth)
            throws Exception {
        resumeSession(
                new FileCert[] { SM_INTCA_CERT },
                new FileCert[] { SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.CURVESM2,
                SignatureScheme.SM2SIG_SM3,
                true,
                clientAuth);

        resumeSession(
                new FileCert[] { SM_INTCA_CERT },
                new FileCert[] { SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_SM4_GCM_SM3,
                NamedGroup.CURVESM2,
                SignatureScheme.SM2SIG_SM3,
                true,
                clientAuth);
    }

    @Test
    public void testResumptionWithECDSACertP256CurveOnTLS12() throws Exception {
        testResumptionWithECDSACertP256CurveOnTLS12(false, ClientAuth.NONE);
        testResumptionWithECDSACertP256CurveOnTLS12(true, ClientAuth.NONE);
        testResumptionWithECDSACertP256CurveOnTLS12(false, ClientAuth.REQUIRED);
        testResumptionWithECDSACertP256CurveOnTLS12(true, ClientAuth.REQUIRED);
    }

    private void testResumptionWithECDSACertP256CurveOnTLS12(
            boolean isUseSessTicket, ClientAuth clientAuth) throws Exception {
        resumeSession(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_2,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                isUseSessTicket,
                clientAuth);

        resumeSession(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_2,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                isUseSessTicket,
                clientAuth);
    }

    private void resumeSession(
            FileCert[] trustedCerts,
            FileCert[] eeCerts,
            Protocol clientProtocol,
            CipherSuite clientCipherSuite,
            NamedGroup clientNamedGroup,
            SignatureScheme clientSignatureScheme,
            boolean isUseSessTicket,
            ClientAuth clientAuth) throws Exception {
        CertTuple certTuple = new CertTuple(trustedCerts, eeCerts);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        OpenSSLServer.Builder serverBuilder = new OpenSSLServer.Builder();
        serverBuilder.setCertTuple(certTuple);
        serverBuilder.setProtocols(Protocol.TLSV1_3, Protocol.TLSV1_2);
        serverBuilder.setCipherSuites(
                CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_SM4_GCM_SM3,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        serverBuilder.setUseSessTicket(isUseSessTicket);
        serverBuilder.setClientAuth(clientAuth);

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            SSLContext context = null;
            long firstCreationTime = 0;
            try (JdkClient client = createClient(
                    certTuple, clientProtocol,
                    clientCipherSuite, clientNamedGroup,
                    clientSignatureScheme,
                    null)) {
                client.connect("127.0.0.1", server.getPort());
                context = client.context;
                firstCreationTime = client.getSession().getCreationTime();
            }

            try (JdkClient client = createClient(
                    certTuple, clientProtocol,
                    clientCipherSuite, clientNamedGroup,
                    clientSignatureScheme,
                    context)) {
                client.connect("127.0.0.1", server.getPort());

                long secondCreationTime = client.getSession().getCreationTime();
                Assertions.assertEquals(firstCreationTime, secondCreationTime);
            }
        } finally {
            executor.shutdown();
        }
    }

    private JdkClient createClient(
            CertTuple certTuple, Protocol protocol,
            CipherSuite cipherSuite, NamedGroup namedGroup,
            SignatureScheme signatureScheme,
            SSLContext context) throws Exception {
        JdkClient.Builder builder = new JdkClient.Builder();
        builder.setCertTuple(certTuple);
        builder.setProtocols(protocol);
        builder.setCipherSuites(cipherSuite);
//        builder.setNamedGroups(namedGroup);
//        builder.setSignatureSchemes(signatureScheme);
        builder.setMessage(
                // An HTTP request asks to access the page.
                String.format("GET /%s HTTP/1.1\r\n", PAGE_FILE_NAME));
        builder.setReadResponse(true);
        builder.setContext(context);
        return builder.build();
    }
}
