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
import com.tencent.kona.ssl.interop.Cert;
import com.tencent.kona.ssl.interop.CertTuple;
import com.tencent.kona.ssl.interop.ContextProtocol;
import com.tencent.kona.ssl.interop.FileCert;
import com.tencent.kona.ssl.interop.HashAlgorithm;
import com.tencent.kona.ssl.interop.JdkClient;
import com.tencent.kona.ssl.interop.JdkProcServer;
import com.tencent.kona.ssl.interop.KeyAlgorithm;
import com.tencent.kona.ssl.interop.Protocol;
import com.tencent.kona.ssl.interop.Server;
import com.tencent.kona.ssl.interop.ServerCaller;
import com.tencent.kona.ssl.interop.SignatureAlgorithm;
import com.tencent.kona.ssl.interop.SmCertTuple;
import com.tencent.kona.ssl.interop.Utilities;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.net.Socket;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Handshake-level coverage of the TLCP enc certificate verification.
 *
 * <p>The sign certificate and the CA chain are always valid. Only the enc
 * certificate is bad, and every bad enc certificate keeps the same subject as
 * the sign certificate, so the rejection can only come from the enc
 * certificate verification rather than from the other checks.
 *
 * <p>The peer that presents the bad enc certificate is always in compat mode,
 * otherwise it would refuse to build the certificate list. Only the verifying
 * side differs between the strict and the compat cases.
 */
public class TlcpEncCertChainTest {

    private static final String COMPAT_PROP
            = "com.tencent.kona.ssl.tlcpDualCertCompat";

    @BeforeAll
    public static void setup() throws IOException {
        TestUtils.addProviders();
    }

    private static FileCert encCert(String name) {
        return new FileCert(
                KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
                "tlcp-enc", name + ".crt", name + ".key");
    }

    // ---- The client verifies the enc certificate presented by the server

    @Test
    public void testServerEncForgedIssuer() {
        assertServerEncRejected("server-enc-forged", "bad_certificate", "signature");
    }

    @Test
    public void testServerEncIsCA() {
        assertServerEncRejected("server-enc-ca", "bad_certificate", "must not be ca");
    }

    @Test
    public void testServerEncWrongEku() {
        assertServerEncRejected("server-enc-eku", "certificate_unknown", "extended key usage");
    }

    @Test
    public void testServerEncExpired() {
        assertServerEncRejected("server-enc-expired", "certificate_expired", "expired", "notafter", "validity");
    }

    @Test
    public void testServerEncRejectedWithSunX509() {
        String[][] cases = {
                {"server-enc-forged", "bad_certificate"},
                {"server-enc-eku", "certificate_unknown"},
                {"server-enc-expired", "certificate_expired"}};
        for (String[] c : cases) {
            Throwable t = Assertions.assertThrows(IOException.class, () ->
                    connectToBadServer(encCert(c[0]),
                            CipherSuite.TLCP_ECC_SM4_CBC_SM3, "SunX509"),
                    c[0]);
            assertReason(c[0], t, c[1]);
        }
    }

    @Test
    public void testServerGoodEncWithSunX509() throws Exception {
        connectToBadServer(TlcpUtils.SERVER_ENC_CERT,
                CipherSuite.TLCP_ECC_SM4_CBC_SM3, "SunX509");
        connectToBadServer(TlcpUtils.SERVER_ENC_CERT,
                CipherSuite.TLCP_ECDHE_SM4_CBC_SM3, "SunX509");
    }

    @Test
    public void testServerGoodEncWithPKIX() throws Exception {
        connectToBadServer(TlcpUtils.SERVER_ENC_CERT,
                CipherSuite.TLCP_ECC_SM4_CBC_SM3, "PKIX");
        connectToBadServer(TlcpUtils.SERVER_ENC_CERT,
                CipherSuite.TLCP_ECDHE_SM4_CBC_SM3, "PKIX");
    }

    // The rejection must come from the enc certificate verification, so the
    // failure reason is checked against the whole cause chain.
    private void assertServerEncRejected(String name, String alert,
            String... reasons) {
        FileCert badEnc = encCert(name);
        for (CipherSuite suite : new CipherSuite[] {
                CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                CipherSuite.TLCP_ECDHE_SM4_CBC_SM3}) {
            Throwable t = Assertions.assertThrows(IOException.class, () ->
                    connectToBadServer(badEnc, suite, "PKIX"),
                    name + " must be rejected by a strict client");
            assertReason(name, t, alert, reasons);

            // The legacy compat client does not verify the enc certificate.
            try {
                TlcpUtils.withDualCertCompat(() ->
                        connectToBadServer(badEnc, suite, "PKIX"));
            } catch (Exception e) {
                Assertions.fail(name + " must be accepted by a compat client", e);
            }
        }
    }

    private static void assertReason(String name, Throwable t, String alert,
            String... reasons) {
        StringBuilder all = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause()) {
            all.append(c).append(" | ");
        }
        assertText(name, all.toString(), alert, reasons);
    }

    private static void assertText(String name, String text, String alert,
            String... reasons) {
        String msg = text.toLowerCase();
        Assertions.assertTrue(msg.contains(alert),
                name + " expects alert " + alert + " but got: " + text);
        if (reasons.length == 0) {
            return;
        }
        for (String reason : reasons) {
            if (msg.contains(reason.toLowerCase())) {
                return;
            }
        }
        Assertions.fail(name + " was rejected for another reason: " + text);
    }

    private void connectToBadServer(FileCert serverEncCert,
            CipherSuite suite, String trustManagerAlgo) throws Exception {
        connectToBadServer(serverEncCert, suite, trustManagerAlgo, null, null);
    }

    private void connectToBadServer(FileCert serverEncCert,
            CipherSuite suite, String trustManagerAlgo,
            Cert[] clientTrusted, SSLContext clientContext) throws Exception {
        SmCertTuple serverCertTuple = new SmCertTuple(
                TlcpUtils.CA_CERT,
                TlcpUtils.SERVER_SIGN_CERT, serverEncCert,
                TlcpUtils.INTCA_CERT);
        CertTuple clientCertTuple = suite.name().startsWith("TLCP_ECDHE")
                ? new SmCertTuple(TlcpUtils.CA_CERT,
                        TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                        TlcpUtils.INTCA_CERT)
                : new SmCertTuple(TlcpUtils.CA_CERT);
        if (clientTrusted != null) {
            clientCertTuple = new CertTuple(clientTrusted,
                    clientCertTuple.endEntityCerts);
        }

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkProcServer.Builder serverBuilder = new JdkProcServer.Builder();
        serverBuilder.setContextProtocol(ContextProtocol.TLCP11);
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.setClientAuth(ClientAuth.NONE);
        serverBuilder.setMessage("Server");
        // The server must be able to build the bad certificate list.
        serverBuilder.addProp(COMPAT_PROP, "true");

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            JdkClient.Builder clientBuilder = new JdkClient.Builder();
            clientBuilder.setContextProtocol(ContextProtocol.TLCP11);
            clientBuilder.setCertTuple(clientCertTuple);
            clientBuilder.setProtocols(Protocol.TLCPV1_1);
            clientBuilder.setCipherSuites(suite);
            clientBuilder.setTrustManagerAlgo(trustManagerAlgo);
            clientBuilder.setMessage("Client");
            clientBuilder.setReadResponse(true);
            if (clientContext != null) {
                clientBuilder.setContext(clientContext);
            }

            try (Client client = clientBuilder.build()) {
                client.connect("127.0.0.1", server.getPort());
            }
        } finally {
            executor.shutdown();
        }
    }

    // The trust store holds two CAs with the same name but different keys.
    // The enc certificate is issued by the one that did not issue the sign
    // certificate, so it is valid on its own, but not under the CA key that
    // is in the sign certificate's path.
    @Test
    public void testServerEncIssuedBySameNameDifferentKeyAnchor()
            throws Exception {
        Cert[] trusted = { TlcpUtils.INTCA_CERT, encCert("rogue-intca") };
        Throwable t = Assertions.assertThrows(IOException.class, () ->
                connectToBadServer(encCert("server-enc-forged"),
                        CipherSuite.TLCP_ECC_SM4_CBC_SM3, "PKIX",
                        trusted, null));
        assertReason("same-name anchors", t, "bad_certificate", "same ca key");

        TlcpUtils.withDualCertCompat(() -> connectToBadServer(
                encCert("server-enc-forged"),
                CipherSuite.TLCP_ECC_SM4_CBC_SM3, "PKIX", trusted, null));
    }

    // The direct issuer of both certificates is itself the trust anchor.
    @Test
    public void testDirectIssuerIsTrustAnchor() throws Exception {
        Cert[] trusted = { TlcpUtils.INTCA_CERT };
        for (String tm : new String[] { "PKIX", "SunX509" }) {
            for (CipherSuite suite : new CipherSuite[] {
                    CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                    CipherSuite.TLCP_ECDHE_SM4_CBC_SM3}) {
                connectToBadServer(TlcpUtils.SERVER_ENC_CERT, suite, tm,
                        trusted, null);
            }
        }
    }

    // A custom trust manager only validates the sign chain, so the new
    // non-CA rule of the built-in trust managers must not apply to it either.
    @Test
    public void testCustomTrustManagerSkipsEncChecks() throws Exception {
        connectToBadServer(encCert("server-enc-ca"),
                CipherSuite.TLCP_ECC_SM4_CBC_SM3, "PKIX", null,
                createTrustAllContext());
        connectToBadServer(encCert("server-enc-expired"),
                CipherSuite.TLCP_ECC_SM4_CBC_SM3, "PKIX", null,
                createTrustAllContext());
    }

    private static SSLContext createTrustAllContext() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(
                KeyStore.getDefaultType(), "KonaPKIX");
        keyStore.load(null, null);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm(), "KonaSSL");
        kmf.init(keyStore, new char[0]);

        SSLContext context = SSLContext.getInstance(
                ContextProtocol.TLCP11.name, "KonaSSL");
        context.init(kmf.getKeyManagers(),
                new javax.net.ssl.TrustManager[] { new TrustAllManager() },
                null);
        return context;
    }

    private static final class TrustAllManager extends X509ExtendedTrustManager {
        @Override public void checkClientTrusted(X509Certificate[] c, String a) { }
        @Override public void checkServerTrusted(X509Certificate[] c, String a) { }
        @Override public void checkClientTrusted(X509Certificate[] c, String a, Socket s) { }
        @Override public void checkServerTrusted(X509Certificate[] c, String a, Socket s) { }
        @Override public void checkClientTrusted(X509Certificate[] c, String a, SSLEngine e) { }
        @Override public void checkServerTrusted(X509Certificate[] c, String a, SSLEngine e) { }
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    // ---- The server verifies the enc certificate presented by the client

    @Test
    public void testClientEncForgedIssuer() throws Exception {
        assertClientEncRejected("client-enc-forged", "certificate_unknown", "signature");
    }

    @Test
    public void testClientEncIsCA() throws Exception {
        assertClientEncRejected("client-enc-ca", "bad_certificate", "must not be ca");
    }

    @Test
    public void testClientEncWrongEku() throws Exception {
        assertClientEncRejected("client-enc-eku", "certificate_unknown", "extended key usage");
    }

    @Test
    public void testClientEncExpired() throws Exception {
        assertClientEncRejected("client-enc-expired", "certificate_unknown", "expired", "notafter", "validity");
    }

    // The server log must carry the target reason, otherwise another
    // handshake error could be mistaken for the enc certificate rejection.
    private void assertClientEncRejected(String name, String alert,
            String... reasons) throws Exception {
        FileCert badEnc = encCert(name);
        for (CipherSuite suite : new CipherSuite[] {
                CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                CipherSuite.TLCP_ECDHE_SM4_CBC_SM3}) {
            TlcpUtils.withDualCertCompat(() -> {
                StringBuilder serverLog = new StringBuilder();
                Assertions.assertThrows(IOException.class, () ->
                        connectWithBadClient(badEnc, suite, false, serverLog),
                        name + " must be rejected by a strict server");
                assertText(name + " (server log)", serverLog.toString(),
                        alert, reasons);

                // The legacy compat server does not verify the enc certificate.
                connectWithBadClient(badEnc, suite, true, null);
            });
        }
    }

    // The client always runs in compat mode (the caller wraps it), so that it
    // actually emits the bad certificate list.
    private void connectWithBadClient(FileCert clientEncCert,
            CipherSuite suite, boolean serverCompat, StringBuilder serverLog)
            throws Exception {
        SmCertTuple serverCertTuple = new SmCertTuple(
                TlcpUtils.CA_CERT,
                TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                TlcpUtils.INTCA_CERT);
        SmCertTuple clientCertTuple = new SmCertTuple(
                TlcpUtils.CA_CERT,
                TlcpUtils.CLIENT_SIGN_CERT, clientEncCert,
                TlcpUtils.INTCA_CERT);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkProcServer.Builder serverBuilder = new JdkProcServer.Builder();
        serverBuilder.setContextProtocol(ContextProtocol.TLCP11);
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.setClientAuth(ClientAuth.REQUIRED);
        serverBuilder.setMessage("Server");
        serverBuilder.addProp(COMPAT_PROP, Boolean.toString(serverCompat));

        try (Server server = serverBuilder.build()) {
            Future<Void> serverFuture =
                    executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            JdkClient.Builder clientBuilder = new JdkClient.Builder();
            clientBuilder.setContextProtocol(ContextProtocol.TLCP11);
            clientBuilder.setCertTuple(clientCertTuple);
            clientBuilder.setProtocols(Protocol.TLCPV1_1);
            clientBuilder.setCipherSuites(suite);
            clientBuilder.setMessage("Client");
            clientBuilder.setReadResponse(true);

            try (Client client = clientBuilder.build()) {
                client.connect("127.0.0.1", server.getPort());
            } finally {
                if (serverLog != null) {
                    try {
                        serverFuture.get(60, TimeUnit.SECONDS);
                    } catch (ExecutionException | TimeoutException e) {
                        // The strict server exits abnormally; its log has
                        // the reason.
                    }
                    Path logPath = ((JdkProcServer) server).getLogPath();
                    serverLog.append(Utilities.readFile(logPath).orElse(""));
                }
            }
        } finally {
            executor.shutdown();
        }
    }
}
