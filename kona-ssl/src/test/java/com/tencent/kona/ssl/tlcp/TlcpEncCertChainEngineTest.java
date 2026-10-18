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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * The SSLEngine counterpart of {@link TlcpEncCertChainTest}: a bad enc
 * certificate presented by one engine must be rejected by the other engine
 * when it is in the strict mode.
 *
 * <p>Both engines run in this JVM, so the compat switch applies to both. A
 * strict producer accepts these enc certificates (they form a valid pair with
 * the sign certificate), so the strict cases need no compat producer.
 */
public class TlcpEncCertChainEngineTest {

    private static final String[] CIPHER_SUITES = {
            "TLCP_ECC_SM4_GCM_SM3", "TLCP_ECDHE_SM4_GCM_SM3"};

    private static final int MAX_ROUNDS = 40;

    private static final char[] PASSPHRASE = "passphrase".toCharArray();

    // TLS record and handshake message types
    private static final int RECORD_HANDSHAKE = 22;
    private static final int HS_CLIENT_KEY_EXCHANGE = 16;

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    // ---- The client engine verifies the enc certificate of the server

    @Test
    public void testServerEncRejected() throws Exception {
        for (String tm : new String[] { "PKIX", "SunX509" }) {
            for (String suite : CIPHER_SUITES) {
                boolean pkix = tm.equals("PKIX");
                // The trust anchor is the direct issuer: PKIX reports that no
                // anchor verifies the path, SimpleValidator a signature error.
                assertRejected(tm, suite, "server-enc-forged", true,
                        pkix ? "certificate_unknown" : "bad_certificate",
                        pkix ? "does not chain" : null);
                assertRejected(tm, suite, "server-enc-eku", true,
                        "certificate_unknown",
                        pkix ? "extended key usage" : null);
                assertRejected(tm, suite, "server-enc-expired", true,
                        "certificate_expired", null);
            }
        }
        for (String suite : CIPHER_SUITES) {
            assertRejected("PKIX", suite, "server-enc-ca", true,
                    "bad_certificate", "must not be ca");
        }
    }

    // ---- The server engine verifies the enc certificate of the client

    @Test
    public void testClientEncRejected() throws Exception {
        for (String tm : new String[] { "PKIX", "SunX509" }) {
            for (String suite : CIPHER_SUITES) {
                boolean pkix = tm.equals("PKIX");
                assertRejected(tm, suite, "client-enc-forged", false,
                        "certificate_unknown", pkix ? "does not chain" : null);
                assertRejected(tm, suite, "client-enc-eku", false,
                        "certificate_unknown",
                        pkix ? "extended key usage" : null);
                assertRejected(tm, suite, "client-enc-expired", false,
                        "certificate_unknown", null);
            }
        }
        for (String suite : CIPHER_SUITES) {
            assertRejected("PKIX", suite, "client-enc-ca", false,
                    "bad_certificate", "must not be ca");
        }
    }

    // The compat mode does not verify the enc certificate, on either side.
    @Test
    public void testCompatAcceptsBadEnc() throws Exception {
        TlcpUtils.withDualCertCompat(() -> {
            for (String suite : CIPHER_SUITES) {
                Outcome o = handshake("PKIX", suite, "server-enc-forged", null);
                Assertions.assertNull(o.failure, "server enc: " + o.failure);
                Assertions.assertTrue(o.completed, "server enc: " + suite);
                o = handshake("PKIX", suite, null, "client-enc-forged");
                Assertions.assertNull(o.failure, "client enc: " + o.failure);
                Assertions.assertTrue(o.completed, "client enc: " + suite);
            }
        });
    }

    @Test
    public void testGoodEnc() throws Exception {
        for (String tm : new String[] { "PKIX", "SunX509" }) {
            for (String suite : CIPHER_SUITES) {
                Outcome o = handshake(tm, suite, null, null);
                Assertions.assertNull(o.failure, tm + ": " + o.failure);
                Assertions.assertTrue(o.completed, tm + " " + suite);
                // The reference for the "no CKE" assertions: a good
                // handshake must show a ClientKeyExchange.
                Assertions.assertTrue(o.clientSentCke, tm + " " + suite);
            }
        }
    }

    private void assertRejected(String tm, String suite, String badEnc,
            boolean serverIsBad, String alert, String reason)
            throws Exception {
        String desc = tm + " " + suite + " " + badEnc;
        Outcome o = handshake(tm, suite,
                serverIsBad ? badEnc : null, serverIsBad ? null : badEnc);

        Assertions.assertFalse(o.completed, desc + " must not complete");
        Assertions.assertNotNull(o.failure, desc + " must be rejected");
        StringBuilder chain = new StringBuilder();
        for (Throwable t = o.failure; t != null; t = t.getCause()) {
            chain.append(t).append(" | ");
        }
        String text = chain.toString().toLowerCase();
        Assertions.assertTrue(text.contains(alert),
                desc + " expects alert " + alert + " but got: " + chain);
        if (reason != null) {
            Assertions.assertTrue(text.contains(reason),
                    desc + " expects reason '" + reason + "' but got: " + chain);
        }

        // The rejecting engine must be the one that verifies the bad enc
        // certificate.
        Assertions.assertEquals(serverIsBad ? "client" : "server",
                o.failedEngine, desc);

        // A client that rejects the server certificate never sends a
        // ClientKeyExchange.
        if (serverIsBad) {
            Assertions.assertFalse(o.clientSentCke,
                    desc + ": ClientKeyExchange must not be sent");
        }
    }

    private static final class Outcome {
        SSLException failure;
        String failedEngine;
        boolean clientSentCke;
        boolean completed;
    }

    // Drive both engines until the handshake is done or one of them fails.
    private Outcome handshake(String tm, String suite,
            String serverEnc, String clientEnc) throws Exception {
        SSLEngine server = context(tm, "tlcp-server-sign", serverEnc,
                "tlcp-server-enc").createSSLEngine();
        server.setUseClientMode(false);
        server.setNeedClientAuth(true);
        server.setEnabledCipherSuites(new String[] { suite });

        SSLEngine client = context(tm, "tlcp-client-sign", clientEnc,
                "tlcp-client-enc").createSSLEngine();
        client.setUseClientMode(true);
        client.setEnabledCipherSuites(new String[] { suite });

        int appMax = client.getSession().getApplicationBufferSize();
        int netMax = client.getSession().getPacketBufferSize();
        ByteBuffer clientIn = ByteBuffer.allocate(appMax + 50);
        ByteBuffer serverIn = ByteBuffer.allocate(appMax + 50);
        ByteBuffer cTOs = ByteBuffer.allocateDirect(netMax);
        ByteBuffer sTOc = ByteBuffer.allocateDirect(netMax);
        ByteBuffer empty = ByteBuffer.allocate(0);

        Outcome outcome = new Outcome();
        List<byte[]> clientBytes = new ArrayList<>();
        String current = null;
        try {
            for (int i = 0; i < MAX_ROUNDS; i++) {
                current = "client";
                int before = cTOs.position();
                client.wrap(empty, cTOs);
                clientBytes.add(copy(cTOs, before, cTOs.position()));
                runTasks(client);

                current = "server";
                server.wrap(empty, sTOc);
                runTasks(server);

                cTOs.flip();
                sTOc.flip();

                current = "client";
                client.unwrap(sTOc, clientIn);
                runTasks(client);

                current = "server";
                server.unwrap(cTOs, serverIn);
                runTasks(server);

                cTOs.compact();
                sTOc.compact();

                if (i > 0 && client.getHandshakeStatus()
                                == HandshakeStatus.NOT_HANDSHAKING
                        && server.getHandshakeStatus()
                                == HandshakeStatus.NOT_HANDSHAKING) {
                    outcome.completed = true;
                    break;
                }
            }

            // Running out of rounds without a failure is a stalled
            // handshake, which must not be mistaken for a success.
            if (!outcome.completed) {
                Assertions.fail("The handshake neither completed nor failed in "
                        + MAX_ROUNDS + " rounds: client="
                        + client.getHandshakeStatus() + ", server="
                        + server.getHandshakeStatus());
            }
        } catch (SSLException e) {
            outcome.failure = e;
            outcome.failedEngine = current;
        }

        outcome.clientSentCke = containsCke(clientBytes);
        return outcome;
    }

    private static void runTasks(SSLEngine engine) {
        if (engine.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
            Runnable task;
            while ((task = engine.getDelegatedTask()) != null) {
                task.run();
            }
        }
    }

    private static byte[] copy(ByteBuffer buf, int from, int to) {
        ByteBuffer dup = buf.duplicate();
        dup.position(from);
        dup.limit(to);
        byte[] bytes = new byte[dup.remaining()];
        dup.get(bytes);
        return bytes;
    }

    // The client records before ChangeCipherSpec are plaintext, so the
    // handshake message type can be read from the record fragment.
    private static boolean containsCke(List<byte[]> chunks) {
        ByteArrayBuilder all = new ByteArrayBuilder();
        for (byte[] chunk : chunks) {
            all.append(chunk);
        }

        byte[] data = all.bytes();
        int pos = 0;
        while (pos + 5 <= data.length) {
            int type = data[pos] & 0xFF;
            int len = ((data[pos + 3] & 0xFF) << 8) | (data[pos + 4] & 0xFF);
            if (type == RECORD_HANDSHAKE) {
                // Several handshake messages can share one record.
                int hs = pos + 5;
                int end = Math.min(pos + 5 + len, data.length);
                while (hs + 4 <= end) {
                    if ((data[hs] & 0xFF) == HS_CLIENT_KEY_EXCHANGE) {
                        return true;
                    }
                    int hsLen = ((data[hs + 1] & 0xFF) << 16)
                            | ((data[hs + 2] & 0xFF) << 8)
                            | (data[hs + 3] & 0xFF);
                    hs += 4 + hsLen;
                }
            }
            if (type == 20) {   // ChangeCipherSpec: later records are encrypted
                break;
            }
            pos += 5 + len;
        }
        return false;
    }

    private static final class ByteArrayBuilder {
        private final java.io.ByteArrayOutputStream out =
                new java.io.ByteArrayOutputStream();

        void append(byte[] bytes) {
            out.write(bytes, 0, bytes.length);
        }

        byte[] bytes() {
            return out.toByteArray();
        }
    }

    // The sign certificate and the CA are always the good ones; the enc
    // certificate is replaced with the bad one if it is specified.
    private static SSLContext context(String tm, String signName,
            String badEnc, String goodEncName) throws Exception {
        CertificateFactory cf =
                CertificateFactory.getInstance("X.509", "KonaPKIX");

        KeyStore ts = KeyStore.getInstance("PKCS12", "KonaPKIX");
        ts.load(null, null);
        ts.setCertificateEntry("trusted-intca", cert(cf, "tlcp",
                "tlcp-intca.crt"));

        KeyStore ks = KeyStore.getInstance("PKCS12", "KonaPKIX");
        ks.load(null, null);
        addKey(ks, cf, "sign", "tlcp", signName);
        if (badEnc != null) {
            addKey(ks, cf, "enc", "tlcp-enc", badEnc);
        } else {
            addKey(ks, cf, "enc", "tlcp", goodEncName);
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(tm, "KonaSSL");
        tmf.init(ts);
        KeyManagerFactory kmf =
                KeyManagerFactory.getInstance("NewSunX509", "KonaSSL");
        kmf.init(ks, PASSPHRASE);

        SSLContext context = SSLContext.getInstance("TLCP", "KonaSSL");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return context;
    }

    private static Certificate cert(CertificateFactory cf, String dir,
            String file) throws Exception {
        return cf.generateCertificate(new ByteArrayInputStream(
                TestUtils.certStr(dir, file).getBytes()));
    }

    private static void addKey(KeyStore ks, CertificateFactory cf,
            String alias, String dir, String name) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
                Base64.getMimeDecoder().decode(
                        TestUtils.keyStr(dir, name + ".key")));
        PrivateKey key = KeyFactory.getInstance("EC", CryptoInsts.PROV)
                .generatePrivate(keySpec);
        ks.setKeyEntry("cert-" + alias, key, PASSPHRASE,
                new Certificate[] { cert(cf, dir, name + ".crt") });
    }
}
