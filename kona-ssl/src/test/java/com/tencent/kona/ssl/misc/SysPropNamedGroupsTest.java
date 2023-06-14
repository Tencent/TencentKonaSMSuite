/*
 * Copyright (c) 2016, 2021, Oracle and/or its affiliates. All rights reserved.
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
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

//
// Please run in othervm mode.  SunJSSE does not support dynamic system
// properties, no way to re-use system properties in samevm/agentvm mode.
//

package com.tencent.kona.ssl.misc;

import com.tencent.kona.ssl.TestUtils;
import com.tencent.kona.ssl.interop.CertTuple;
import com.tencent.kona.ssl.interop.CipherSuite;
import com.tencent.kona.ssl.interop.Client;
import com.tencent.kona.ssl.interop.ClientAuth;
import com.tencent.kona.ssl.interop.FileCert;
import com.tencent.kona.ssl.interop.HashAlgorithm;
import com.tencent.kona.ssl.interop.JdkProcClient;
import com.tencent.kona.ssl.interop.JdkProcServer;
import com.tencent.kona.ssl.interop.KeyAlgorithm;
import com.tencent.kona.ssl.interop.NamedGroup;
import com.tencent.kona.ssl.interop.Protocol;
import com.tencent.kona.ssl.interop.SSLTestException;
import com.tencent.kona.ssl.interop.Server;
import com.tencent.kona.ssl.interop.ServerCaller;
import com.tencent.kona.ssl.interop.SignatureAlgorithm;
import com.tencent.kona.ssl.interop.Utilities;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Use an unknown named group, and make sure the handshaking must fail.
 * It can check if the system property com.tencent.kona.ssl.namedGroups
 * is renamed by accident.
 */
public class SysPropNamedGroupsTest {

    private static final FileCert SM_INTCA_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "intca-sm2sm2-sm2sm2.crt",
            "intca-sm2sm2-sm2sm2.key");
    private static final FileCert SM_EE_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "ee-sm2sm2-sm2sm2-sm2sm2.crt",
            "ee-sm2sm2-sm2sm2-sm2sm2.key");

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testSysPropNamedGroups() throws Exception {
        Assertions.assertThrows(SSLTestException.class, this::connect);
    }

    private void connect() throws Exception {
        CertTuple serverCertTuple = new CertTuple(SM_INTCA_CERT, SM_EE_CERT);
        CertTuple clientCertTuple = new CertTuple(SM_INTCA_CERT, SM_EE_CERT);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkProcServer.Builder serverBuilder = new JdkProcServer.Builder();
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.setProtocols(Protocol.TLSV1_3);
        serverBuilder.setCipherSuites(
                CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_SM4_GCM_SM3,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        serverBuilder.setNamedGroups(NamedGroup.CURVESM2);
        serverBuilder.setMessage("Server");
        serverBuilder.setClientAuth(ClientAuth.NONE);

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            JdkProcClient.Builder builder = new JdkProcClient.Builder();
            builder.setCertTuple(clientCertTuple);
            builder.setProtocols(Protocol.TLSV1_3);
            builder.setCipherSuites(CipherSuite.TLS_SM4_GCM_SM3);
            builder.setNamedGroups(NamedGroup.SECP256R1);
            builder.setMessage("Client");
            builder.setReadResponse(true);
            try (Client client = builder.build()) {
                client.connect("127.0.0.1", server.getPort());
            }
        } finally {
            executor.shutdown();
        }
    }
}
