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

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.ssl.TestUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * A single certificate serving both the sign and enc roles must be rejected
 * unconditionally — even when the {@code com.tencent.kona.ssl.tlcpDualCertCompat}
 * property is enabled. A TLCP certificate message must always carry two
 * distinct certificates.
 *
 * <p>Uses an in-process SSLEngine handshake so the system property, read by
 * the consumer/producer code paths, takes effect directly.
 */
public class TlcpDualCertCompatTest {

    private static final String PROP = "com.tencent.kona.ssl.tlcpDualCertCompat";
    private static final char[] PASS = "passphrase".toCharArray();
    private static final String SUITE = "TLCP_ECC_SM4_GCM_SM3";

    // Dual-keyUsage single certificates (CN=tlcp-server / CN=tlcp-client),
    // issued by tlcp-intca, each serving both roles.
    private static final String SERVER_CERT = TestUtils.certStr("tlcp", "tlcp-server.crt");
    private static final String SERVER_KEY = TestUtils.keyStr("tlcp", "tlcp-server.key");
    private static final String CLIENT_CERT = TestUtils.certStr("tlcp", "tlcp-client.crt");
    private static final String CLIENT_KEY = TestUtils.keyStr("tlcp", "tlcp-client.key");
    private static final String INTCA_CERT = TestUtils.certStr("tlcp", "tlcp-intca.crt");

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @AfterEach
    public void clearProp() {
        System.clearProperty(PROP);
    }

    @Test
    public void singleCertRejectedByDefault() {
        System.clearProperty(PROP);
        Assertions.assertThrows(SSLException.class, this::singleCertHandshake);
    }

    @Test
    public void singleCertRejectedEvenInCompatMode() {
        // A single certificate serving both roles is rejected unconditionally,
        // even with the dual-cert compat property enabled.
        System.setProperty(PROP, "true");
        Assertions.assertThrows(SSLException.class, this::singleCertHandshake);
    }

    // A TLCP mutual-auth handshake where both peers present a single dual-KU
    // certificate for both the sign and enc roles.
    private void singleCertHandshake() throws Exception {
        SSLEngine server = createContext(SERVER_CERT, SERVER_KEY).createSSLEngine();
        server.setUseClientMode(false);
        server.setNeedClientAuth(true);
        server.setEnabledCipherSuites(new String[] { SUITE });

        SSLEngine client = createContext(CLIENT_CERT, CLIENT_KEY).createSSLEngine();
        client.setUseClientMode(true);
        client.setEnabledCipherSuites(new String[] { SUITE });

        drive(client, server);

        // Reaching here means the handshake finished; confirm it really did.
        Assertions.assertEquals(SUITE, client.getSession().getCipherSuite());
        Assertions.assertEquals(SUITE, server.getSession().getCipherSuite());
    }

    private static SSLContext createContext(String certPem, String keyPem)
            throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "KonaPKIX");

        KeyStore ts = KeyStore.getInstance("PKCS12", "KonaPKIX");
        ts.load(null, null);
        ts.setCertificateEntry("intca", cf.generateCertificate(
                new ByteArrayInputStream(INTCA_CERT.getBytes(StandardCharsets.UTF_8))));

        KeyStore ks = KeyStore.getInstance("PKCS12", "KonaPKIX");
        ks.load(null, null);
        PrivateKey key = KeyFactory.getInstance("EC", CryptoInsts.PROV)
                .generatePrivate(new PKCS8EncodedKeySpec(
                        Base64.getMimeDecoder().decode(keyPem)));
        Certificate ee = cf.generateCertificate(
                new ByteArrayInputStream(certPem.getBytes(StandardCharsets.UTF_8)));
        ks.setKeyEntry("ee", key, PASS, new Certificate[] { ee });

        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance("PKIX", "KonaSSL");
        tmf.init(ts);
        KeyManagerFactory kmf =
                KeyManagerFactory.getInstance("NewSunX509", "KonaSSL");
        kmf.init(ks, PASS);

        SSLContext context = SSLContext.getInstance("TLCP", "KonaSSL");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return context;
    }

    // Drive the SSLEngine handshake to completion. Any handshake failure
    // surfaces as an SSLException from wrap()/unwrap().
    private static void drive(SSLEngine client, SSLEngine server)
            throws Exception {
        SSLSession session = client.getSession();
        int netMax = session.getPacketBufferSize();
        int appMax = session.getApplicationBufferSize();

        ByteBuffer cOut = ByteBuffer.wrap("client".getBytes(StandardCharsets.UTF_8));
        ByteBuffer sOut = ByteBuffer.wrap("server".getBytes(StandardCharsets.UTF_8));
        ByteBuffer cToS = ByteBuffer.allocate(netMax + 100);
        ByteBuffer sToC = ByteBuffer.allocate(netMax + 100);
        ByteBuffer cIn = ByteBuffer.allocate(appMax + 100);
        ByteBuffer sIn = ByteBuffer.allocate(appMax + 100);

        for (int i = 0; i < 50; i++) {
            client.wrap(cOut, cToS);
            server.wrap(sOut, sToC);
            runTasks(client);
            runTasks(server);

            cToS.flip();
            sToC.flip();

            client.unwrap(sToC, cIn);
            server.unwrap(cToS, sIn);
            runTasks(client);
            runTasks(server);

            cToS.compact();
            sToC.compact();

            if (client.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING
                    && server.getHandshakeStatus() == HandshakeStatus.NOT_HANDSHAKING) {
                return;
            }
        }
        throw new IllegalStateException("TLCP handshake did not complete");
    }

    private static void runTasks(SSLEngine engine) {
        if (engine.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
            Runnable task;
            while ((task = engine.getDelegatedTask()) != null) {
                task.run();
            }
        }
    }
}
