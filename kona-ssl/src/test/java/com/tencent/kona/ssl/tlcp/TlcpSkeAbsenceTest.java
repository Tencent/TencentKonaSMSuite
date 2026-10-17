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
import com.tencent.kona.ssl.interop.ContextProtocol;
import com.tencent.kona.ssl.interop.Provider;
import com.tencent.kona.ssl.interop.SmCertTuple;
import com.tencent.kona.ssl.interop.Utilities;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;

/**
 * Regression coverage for the TLCP ECC-static (K_SM2) ServerKeyExchange (SKE)
 * requirement (vulnerability "TLCP ECC SKE absence / server impersonation").
 *
 * <p>In a TLCP ECC static handshake the SKE carries the only cryptographic
 * binding between the server's sign certificate and its enc certificate (a
 * signature over {@code client_random || server_random || enc_cert}). The
 * client must therefore refuse to continue if the SKE is missing. These tests
 * stand a record-level man-in-the-middle between a stock Kona TLCP server and
 * the Kona TLCP client, and either drop or corrupt the server's SKE.
 *
 * <p><b>Fixture isolation:</b> the server uses the legitimate, same-identity
 * dual certificate pair ({@code CN=tlcp-server} sign + enc, both issued by
 * {@code CN=tlcp-intca}). It passes every existing certificate/pairing check,
 * so a rejection can only come from the SKE-presence guard, not from the
 * TKSS-1308 dual-cert pairing check.
 *
 * <p><b>Observable:</b> the proxy watches the client-&gt;server direction for a
 * ClientKeyExchange (handshake type 16). The guard runs in the ServerHelloDone
 * consumer, before the ClientKeyExchange producer, so a correctly fixed client
 * must abort <em>without</em> ever sending a ClientKeyExchange (i.e. without
 * encrypting the premaster secret to the attacker's enc key).
 *
 * <p>The guard lives in {@code ServerHelloDoneConsumer.consume}, which is the
 * same code path for SSLSocket and SSLEngine; the SSLSocket harness here
 * exercises that logic directly.
 */
public class TlcpSkeAbsenceTest {

    private static final String ECC_CBC = "TLCP_ECC_SM4_CBC_SM3";
    private static final String ECC_GCM = "TLCP_ECC_SM4_GCM_SM3";
    private static final String ECDHE_CBC = "TLCP_ECDHE_SM4_CBC_SM3";

    // Server->client tampering performed by the in-process proxy.
    private enum Tamper {
        NONE,            // faithful pass-through
        DROP_SKE,        // remove the ServerKeyExchange from the stream
        CORRUPT_SKE_SIG  // flip the last signature byte of the ServerKeyExchange
    }

    @BeforeAll
    public static void setup() throws IOException {
        TestUtils.addProviders();
    }

    // ---- Negative: SKE missing (F1 target), both ECC suites ----

    @Test
    public void missingSkeRejectedCbc() throws Exception {
        assertSkeAbsenceRejected(ECC_CBC);
    }

    @Test
    public void missingSkeRejectedGcm() throws Exception {
        assertSkeAbsenceRejected(ECC_GCM);
    }

    // Same guard must fire under the legacy dual-cert compat mode, whose
    // certificate pairing path differs from strict mode.
    @Test
    public void missingSkeRejectedCompat() throws Exception {
        TlcpUtils.withDualCertCompat(() -> assertSkeAbsenceRejected(ECC_CBC));
    }

    // ---- Negative: SKE present but signature invalid, both ECC suites ----
    // Proves the "received" flag means "consumed AND verified": a present but
    // forged SKE must fail at signature verification, not slip through.

    @Test
    public void badSkeSignatureRejectedCbc() throws Exception {
        assertBadSkeSignatureRejected(ECC_CBC);
    }

    @Test
    public void badSkeSignatureRejectedGcm() throws Exception {
        assertBadSkeSignatureRejected(ECC_GCM);
    }

    // ---- Positive: untouched handshakes still succeed (no regression) ----

    @Test
    public void normalEccHandshakeSucceedsCbc() throws Exception {
        Result r = connect(ECC_CBC, Tamper.NONE, false);
        r.rethrowClient();
        Assertions.assertTrue(r.handshakeOk, "normal ECC CBC handshake must succeed");
        Assertions.assertTrue(r.clientKeyExchangeSent,
                "a successful ECC handshake must send ClientKeyExchange");
    }

    @Test
    public void normalEccHandshakeSucceedsGcm() throws Exception {
        Result r = connect(ECC_GCM, Tamper.NONE, false);
        r.rethrowClient();
        Assertions.assertTrue(r.handshakeOk, "normal ECC GCM handshake must succeed");
    }

    @Test
    public void ecdheUnaffected() throws Exception {
        // ECDHE (K_SM2E) is out of scope for the guard; it must still complete.
        // Kona's TLCP ECDHE flow is exercised here with mutual authentication,
        // matching the established working configuration in TlcpDualCertAttackTest.
        Result r = connect(ECDHE_CBC, Tamper.NONE, true);
        r.rethrowClient();
        Assertions.assertTrue(r.handshakeOk, "ECDHE handshake must be unaffected");
    }

    // Pump-lifecycle regression (independent of a real handshake): a
    // ClientKeyExchange record is already queued on the shared downstream
    // socket when the server->client pump hits an immediate EOF and exits
    // FIRST. The s2c pump must not close that shared socket, so the c2s pump
    // must still read and observe the queued ClientKeyExchange. With the former
    // (buggy) code where s2c closed the downstream socket, this scan would be
    // truncated and clientKeyExchangeSent would be false.
    @Test
    public void s2cEarlyExitDoesNotTruncateCkeScan() throws Exception {
        InetAddress loop = InetAddress.getLoopbackAddress();
        Result result = new Result();
        try (ServerSocket dsAcc = new ServerSocket(0, 1, loop);
             ServerSocket usAcc = new ServerSocket(0, 1, loop);
             Socket clientEnd = new Socket(loop, dsAcc.getLocalPort());
             Socket downstream = dsAcc.accept();
             Socket serverEnd = new Socket(loop, usAcc.getLocalPort());
             Socket upstream = usAcc.accept()) {

            // Queue a ClientKeyExchange (record type 22, handshake type 16) on
            // the client->proxy direction, then FIN so c2s sees it then EOF.
            byte[] ckeRecord = {22, 0x01, 0x01, 0x00, 0x04, 16, 0x00, 0x00, 0x00};
            clientEnd.getOutputStream().write(ckeRecord);
            clientEnd.getOutputStream().flush();
            clientEnd.shutdownOutput();

            // Server end closes immediately: s2c sees EOF right away and exits.
            serverEnd.close();

            RecordRewriter rewriter = new RecordRewriter(Tamper.NONE);
            Thread s2c = new Thread(() -> pumpServerToClient(upstream, downstream, rewriter));
            s2c.setDaemon(true);
            s2c.start();
            s2c.join(3000);
            Assertions.assertFalse(s2c.isAlive(), "s2c should exit on the server EOF");

            // Now run c2s AFTER s2c has already exited: it must still read the
            // queued CKE because s2c did not close the shared downstream socket.
            Thread c2s = new Thread(() -> pumpClientToServer(downstream, upstream, result));
            c2s.setDaemon(true);
            c2s.start();
            c2s.join(5000);
            Assertions.assertFalse(c2s.isAlive(), "c2s should drain to EOF and exit");

            Assertions.assertTrue(result.clientKeyExchangeSent,
                    "queued ClientKeyExchange must still be observed even though "
                    + "the server->client pump exited first");
        }
    }

    // ---- SSLEngine negative coverage: the guard lives in the shared
    //      ServerHelloDoneConsumer, so it must fire on the SSLEngine path too.

    @Test
    public void engineMissingSkeRejectedCbc() throws Exception {
        assertEngineSkeAbsenceRejected(ECC_CBC);
    }

    @Test
    public void engineMissingSkeRejectedGcm() throws Exception {
        assertEngineSkeAbsenceRejected(ECC_GCM);
    }

    @Test
    public void engineBadSkeSignatureRejectedCbc() throws Exception {
        assertEngineBadSkeSignatureRejected(ECC_CBC);
    }

    @Test
    public void engineBadSkeSignatureRejectedGcm() throws Exception {
        assertEngineBadSkeSignatureRejected(ECC_GCM);
    }

    @Test
    public void engineNormalEccSucceeds() throws Exception {
        EngineResult r = runEngineHandshake(ECC_CBC, Tamper.NONE);
        Assertions.assertNull(r.failure,
                "normal ECC engine handshake must not fail: " + r.failure);
        Assertions.assertTrue(r.clientFinished,
                "normal ECC engine handshake must complete");
        Assertions.assertTrue(r.clientKeyExchangeSent,
                "a successful ECC engine handshake must send ClientKeyExchange");
    }

    private void assertEngineSkeAbsenceRejected(String suite) throws Exception {
        EngineResult r = runEngineHandshake(suite, Tamper.DROP_SKE);
        Assertions.assertFalse(r.clientFinished,
                "engine handshake must fail when the ECC-static SKE is missing");
        Assertions.assertEquals(1, r.skeDropped,
                "exactly one ServerKeyExchange must have been dropped");
        Assertions.assertNotNull(r.failure, "client engine must raise an exception");
        String msg = String.valueOf(r.failure);
        Assertions.assertTrue(
                msg.contains("ServerKeyExchange is required")
                        && msg.toLowerCase().contains("unexpected_message"),
                "rejection must be the SKE-presence guard, was: " + msg);
        Assertions.assertFalse(r.clientKeyExchangeSent,
                "client must NOT send ClientKeyExchange when the SKE is missing");
        Assertions.assertEquals(10, r.alertDescription,
                "client must emit an unexpected_message alert");
    }

    private void assertEngineBadSkeSignatureRejected(String suite) throws Exception {
        EngineResult r = runEngineHandshake(suite, Tamper.CORRUPT_SKE_SIG);
        Assertions.assertFalse(r.clientFinished,
                "engine handshake must fail when the SKE signature is invalid");
        Assertions.assertEquals(1, r.skeCorrupted,
                "exactly one ServerKeyExchange signature must have been corrupted");
        Assertions.assertNotNull(r.failure, "client engine must raise an exception");
        String msg = String.valueOf(r.failure);
        Assertions.assertTrue(
                msg.contains("SM2 ServerKeyExchange signature")
                        && msg.toLowerCase().contains("handshake_failure"),
                "rejection must be SKE signature verification, was: " + msg);
        Assertions.assertFalse(r.clientKeyExchangeSent,
                "client must NOT send ClientKeyExchange on an invalid SKE");
        Assertions.assertEquals(40, r.alertDescription,
                "client must emit a handshake_failure alert");
    }

    private void assertSkeAbsenceRejected(String suite) throws Exception {
        Result r = connect(suite, Tamper.DROP_SKE, false);
        Assertions.assertFalse(r.handshakeOk,
                "handshake must fail when the ECC-static SKE is missing");
        Assertions.assertEquals(1, r.skeDropped,
                "exactly one ServerKeyExchange must have been dropped");
        Assertions.assertNotNull(r.clientException,
                "client must raise an exception on a missing SKE");
        String msg = String.valueOf(r.clientException);
        // The rejection must be the SKE-presence guard specifically: both the
        // exact reason text and the unexpected_message alert, with no generic
        // fallback that other state-machine violations could also satisfy.
        Assertions.assertTrue(
                msg.contains("ServerKeyExchange is required")
                        && msg.toLowerCase().contains("unexpected_message"),
                "rejection must be the SKE-presence guard, was: " + msg);
        Assertions.assertFalse(r.clientKeyExchangeSent,
                "client must NOT send ClientKeyExchange when the SKE is missing");
    }

    private void assertBadSkeSignatureRejected(String suite) throws Exception {
        Result r = connect(suite, Tamper.CORRUPT_SKE_SIG, false);
        Assertions.assertFalse(r.handshakeOk,
                "handshake must fail when the SKE signature is invalid");
        Assertions.assertEquals(1, r.skeCorrupted,
                "exactly one ServerKeyExchange signature must have been corrupted");
        Assertions.assertNotNull(r.clientException,
                "client must raise an exception on an invalid SKE signature");
        String msg = String.valueOf(r.clientException);
        // Must fail at SKE signature verification (handshake_failure), not at
        // some other negotiation step; assert both the reason and the alert.
        Assertions.assertTrue(
                msg.contains("SM2 ServerKeyExchange signature")
                        && msg.toLowerCase().contains("handshake_failure"),
                "rejection must be SKE signature verification, was: " + msg);
        Assertions.assertFalse(r.clientKeyExchangeSent,
                "client must NOT send ClientKeyExchange on an invalid SKE");
    }

    /* ------------------------------------------------------------------ */
    /* Harness: stock server  <->  record-level proxy  <->  Kona client   */
    /* ------------------------------------------------------------------ */

    private static final class Result {
        volatile boolean handshakeOk;
        volatile Throwable clientException;
        volatile boolean clientKeyExchangeSent;
        volatile boolean clientTimedOut;
        volatile int skeDropped;
        volatile int skeCorrupted;

        void rethrowClient() throws Exception {
            if (clientException instanceof Exception) {
                throw (Exception) clientException;
            } else if (clientException != null) {
                throw new RuntimeException(clientException);
            }
        }
    }

    private Result connect(String suite, Tamper tamper, boolean mutualAuth)
            throws Exception {
        Result result = new Result();

        SSLContext serverCtx = Utilities.createSSLContext(
                Provider.KONA, ContextProtocol.TLCP11,
                new SmCertTuple(TlcpUtils.CA_CERT,
                        TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                        TlcpUtils.INTCA_CERT));
        SSLContext clientCtx = Utilities.createSSLContext(
                Provider.KONA, ContextProtocol.TLCP11,
                mutualAuth
                        ? new SmCertTuple(TlcpUtils.CA_CERT,
                                TlcpUtils.CLIENT_SIGN_CERT, TlcpUtils.CLIENT_ENC_CERT,
                                TlcpUtils.INTCA_CERT)
                        : new SmCertTuple(TlcpUtils.CA_CERT));

        InetAddress loop = InetAddress.getLoopbackAddress();

        try (SSLServerSocket server = (SSLServerSocket)
                serverCtx.getServerSocketFactory().createServerSocket(0, 16, loop);
             ServerSocket proxy = new ServerSocket(0, 16, loop)) {

            if (mutualAuth) {
                server.setNeedClientAuth(true);
            }

            int serverPort = server.getLocalPort();
            int proxyPort = proxy.getLocalPort();

            // Server thread: echo one byte, tolerate handshake failures.
            Thread serverThread = new Thread(() -> {
                try (SSLSocket s = (SSLSocket) server.accept()) {
                    s.setEnabledProtocols(new String[]{"TLCPv1.1"});
                    InputStream in = s.getInputStream();
                    OutputStream out = s.getOutputStream();
                    int b = in.read();
                    if (b >= 0) {
                        out.write(b ^ 0xFF);
                        out.flush();
                    }
                } catch (Exception ignored) {
                    // A dropped/corrupted SKE legitimately breaks the server too.
                }
            });
            serverThread.setDaemon(true);
            serverThread.start();

            // Client thread: drive the handshake through the proxy.
            Thread clientThread = new Thread(() -> {
                try (SSLSocket c = (SSLSocket)
                        clientCtx.getSocketFactory().createSocket(loop, proxyPort)) {
                    c.setEnabledProtocols(new String[]{"TLCPv1.1"});
                    c.setEnabledCipherSuites(new String[]{suite});
                    c.setSoTimeout(15000);
                    OutputStream out = c.getOutputStream();
                    InputStream in = c.getInputStream();
                    out.write(0x42);          // forces the handshake to complete
                    out.flush();
                    in.read();                // read echo
                    result.handshakeOk = true;
                } catch (Throwable t) {
                    result.clientException = t;
                }
            });
            clientThread.setDaemon(true);
            clientThread.start();

            // This thread acts as the proxy: splice the single client connection
            // to the server, applying the configured server->client tampering.
            RecordRewriter rewriter = new RecordRewriter(tamper);
            Socket downstream = proxy.accept();
            Socket upstream = new Socket(loop, serverPort);
            Thread c2s = new Thread(() -> pumpClientToServer(downstream, upstream, result));
            Thread s2c = new Thread(() -> pumpServerToClient(upstream, downstream, rewriter));
            c2s.setDaemon(true);
            s2c.setDaemon(true);
            c2s.start();
            s2c.start();

            // Wait for the client to finish.
            clientThread.join(20000);
            if (clientThread.isAlive()) {
                result.clientTimedOut = true;
            }

            // Drain the client->server pump WITHOUT pre-closing: on both a
            // successful handshake and an SKE rejection the client closes its
            // own socket, so the pump's read loop terminates on its own once it
            // has consumed every queued record (a TCP FIN returns -1; a reset
            // throws only AFTER all buffered bytes have been delivered and read
            // -- either way the whole client->server stream has been scanned).
            // A pump that is STILL blocked after this bounded wait means the
            // client never closed (it hung), so the observation is unreliable.
            // We therefore join first and force-close only afterwards.
            boolean c2sJoined;
            c2s.join(10000);
            c2sJoined = !c2s.isAlive();
            s2c.join(5000);

            // Now it is safe to force-close for cleanup and reclaim threads.
            closeQuietly(downstream);
            closeQuietly(upstream);
            c2s.join(2000);
            s2c.join(2000);

            result.skeDropped = rewriter.droppedSke;
            result.skeCorrupted = rewriter.corruptedSke;

            Assertions.assertFalse(result.clientTimedOut,
                    "client handshake did not complete within the timeout");
            Assertions.assertTrue(c2sJoined,
                    "client->server pump did not terminate on its own; the client "
                    + "stream was not fully drained, so the no-ClientKeyExchange "
                    + "observation would be unreliable");
        }
        return result;
    }

    /* ------------------------------------------------------------------ */
    /* SSLEngine harness: two engines with an in-memory MITM that drops or */
    /* corrupts the server->client ServerKeyExchange via the same rewriter.*/
    /* ------------------------------------------------------------------ */

    private static final class EngineResult {
        boolean clientFinished;
        boolean clientKeyExchangeSent;
        Throwable failure;        // client-side handshake exception, if any
        int alertDescription = -1;  // description of the last alert sent
        int skeDropped;
        int skeCorrupted;
    }

    private EngineResult runEngineHandshake(String suite, Tamper tamper)
            throws Exception {
        SSLContext serverCtx = Utilities.createSSLContext(
                Provider.KONA, ContextProtocol.TLCP11,
                new SmCertTuple(TlcpUtils.CA_CERT,
                        TlcpUtils.SERVER_SIGN_CERT, TlcpUtils.SERVER_ENC_CERT,
                        TlcpUtils.INTCA_CERT));
        SSLContext clientCtx = Utilities.createSSLContext(
                Provider.KONA, ContextProtocol.TLCP11,
                new SmCertTuple(TlcpUtils.CA_CERT));

        SSLEngine serverEngine = serverCtx.createSSLEngine();
        serverEngine.setUseClientMode(false);
        serverEngine.setEnabledProtocols(new String[]{"TLCPv1.1"});

        SSLEngine clientEngine = clientCtx.createSSLEngine();
        clientEngine.setUseClientMode(true);
        clientEngine.setEnabledProtocols(new String[]{"TLCPv1.1"});
        clientEngine.setEnabledCipherSuites(new String[]{suite});

        int netMax = clientEngine.getSession().getPacketBufferSize();
        int appMax = clientEngine.getSession().getApplicationBufferSize();
        ByteBuffer wrapOut = ByteBuffer.allocate(netMax + 64);
        ByteBuffer appIn = ByteBuffer.allocate(appMax + 64);

        RecordRewriter rewriter = new RecordRewriter(tamper);
        RecordScanner scanner = new RecordScanner();
        EngineResult result = new EngineResult();

        // Put both engines into the handshaking state so the first iteration
        // has the client in NEED_WRAP (ClientHello) and the server in
        // NEED_UNWRAP; without this a fresh engine is NOT_HANDSHAKING and the
        // pump never starts.
        clientEngine.beginHandshake();
        serverEngine.beginHandshake();

        // Pending network bytes queued toward each peer.
        ByteArrayOutputStream toClient = new ByteArrayOutputStream();
        ByteArrayOutputStream toServer = new ByteArrayOutputStream();
        ByteBuffer empty = ByteBuffer.allocate(0);

        for (int guard = 0; guard < 500; guard++) {
            boolean acted = false;

            // Server produces its handshake flight; the MITM rewriter drops or
            // corrupts the ServerKeyExchange on the way to the client.
            while (serverEngine.getHandshakeStatus()
                    == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                wrapOut.clear();
                serverEngine.wrap(empty, wrapOut);
                wrapOut.flip();
                if (wrapOut.hasRemaining()) {
                    byte[] raw = new byte[wrapOut.remaining()];
                    wrapOut.get(raw);
                    byte[] rewritten = rewriter.feed(raw, raw.length);
                    if (rewritten.length > 0) {
                        toClient.write(rewritten);
                    }
                }
                runEngineTasks(serverEngine);
                acted = true;
            }

            // Client consumes the (tampered) server bytes; this is where the
            // ServerHelloDone guard / SKE signature check throws.
            if (toClient.size() > 0) {
                ByteBuffer in = ByteBuffer.wrap(toClient.toByteArray());
                try {
                    while (in.hasRemaining()) {
                        appIn.clear();
                        SSLEngineResult res = clientEngine.unwrap(in, appIn);
                        runEngineTasks(clientEngine);
                        acted = true;
                        if (res.getHandshakeStatus()
                                == SSLEngineResult.HandshakeStatus.FINISHED) {
                            result.clientFinished = true;
                        }
                        if (res.getStatus()
                                == SSLEngineResult.Status.BUFFER_UNDERFLOW
                                || res.getStatus() == SSLEngineResult.Status.CLOSED) {
                            break;
                        }
                        if (res.bytesConsumed() == 0
                                && res.getStatus() == SSLEngineResult.Status.OK) {
                            break;
                        }
                    }
                } catch (SSLException e) {
                    result.failure = e;
                    // Queued handshake output (e.g. a ClientKeyExchange
                    // produced before the fatal) must still be observed.
                    drainClientOutbound(clientEngine, wrapOut, scanner, result);
                    result.alertDescription = scanner.alertDescription;
                    result.skeDropped = rewriter.droppedSke;
                    result.skeCorrupted = rewriter.corruptedSke;
                    return result;
                }
                byte[] rem = new byte[in.remaining()];
                in.get(rem);
                toClient.reset();
                toClient.write(rem);
            }

            // Client produces its flight; scan it for a ClientKeyExchange. The
            // SKE guard / signature check may surface as a thrown fatal here
            // (when the client wraps its outgoing alert) rather than on unwrap,
            // so this block captures the client-side failure too.
            try {
                while (clientEngine.getHandshakeStatus()
                        == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                    wrapOut.clear();
                    SSLEngineResult res = clientEngine.wrap(empty, wrapOut);
                    wrapOut.flip();
                    if (wrapOut.hasRemaining()) {
                        byte[] raw = new byte[wrapOut.remaining()];
                        wrapOut.get(raw);
                        scanner.scan(raw, raw.length);
                        if (scanner.sawClientKeyExchange) {
                            result.clientKeyExchangeSent = true;
                        }
                        toServer.write(raw);
                    }
                    runEngineTasks(clientEngine);
                    acted = true;
                    if (res.getHandshakeStatus()
                            == SSLEngineResult.HandshakeStatus.FINISHED) {
                        result.clientFinished = true;
                    }
                }
            } catch (SSLException e) {
                result.failure = e;
                drainClientOutbound(clientEngine, wrapOut, scanner, result);
                result.alertDescription = scanner.alertDescription;
                result.skeDropped = rewriter.droppedSke;
                result.skeCorrupted = rewriter.corruptedSke;
                return result;
            }

            // Server consumes client bytes (best effort; its failure is fine).
            if (toServer.size() > 0) {
                ByteBuffer in = ByteBuffer.wrap(toServer.toByteArray());
                try {
                    while (in.hasRemaining()) {
                        appIn.clear();
                        SSLEngineResult res = serverEngine.unwrap(in, appIn);
                        runEngineTasks(serverEngine);
                        acted = true;
                        if (res.getStatus()
                                == SSLEngineResult.Status.BUFFER_UNDERFLOW
                                || res.getStatus() == SSLEngineResult.Status.CLOSED) {
                            break;
                        }
                        if (res.bytesConsumed() == 0
                                && res.getStatus() == SSLEngineResult.Status.OK) {
                            break;
                        }
                    }
                } catch (SSLException serverSide) {
                    // The server legitimately breaks after the client aborts.
                }
                byte[] rem = new byte[in.remaining()];
                in.get(rem);
                toServer.reset();
                toServer.write(rem);
            }

            if (result.clientFinished) {
                break;
            }
            if (!acted) {
                break;
            }
        }

        result.alertDescription = scanner.alertDescription;
        result.skeDropped = rewriter.droppedSke;
        result.skeCorrupted = rewriter.corruptedSke;
        return result;
    }

    // Bounded drain of whatever the client engine still wants to send after a
    // failure, scanning it all so a late guard cannot hide a ClientKeyExchange.
    private static void drainClientOutbound(SSLEngine client,
            ByteBuffer wrapOut, RecordScanner scanner, EngineResult result) {
        ByteBuffer empty = ByteBuffer.allocate(0);
        for (int i = 0; i < 20 && !client.isOutboundDone(); i++) {
            wrapOut.clear();
            int produced;
            try {
                produced = client.wrap(empty, wrapOut).bytesProduced();
            } catch (SSLException e) {
                continue;   // a rethrown fatal; keep draining within the bound
            }
            wrapOut.flip();
            if (produced > 0) {
                byte[] raw = new byte[wrapOut.remaining()];
                wrapOut.get(raw);
                scanner.scan(raw, raw.length);
                if (scanner.sawClientKeyExchange) {
                    result.clientKeyExchangeSent = true;
                }
            }
            runEngineTasks(client);
            if (produced == 0 && client.getHandshakeStatus()
                    != SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                break;
            }
        }
    }

    private static void runEngineTasks(SSLEngine engine) {
        if (engine.getHandshakeStatus()
                == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            Runnable task;
            while ((task = engine.getDelegatedTask()) != null) {
                task.run();
            }
        }
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (Exception ignored) {
        }
    }

    // client -> server: record whether a ClientKeyExchange (handshake type 16)
    // is ever sent before CCS. Scanning is decoupled from forwarding: if the
    // upstream (server) side breaks, forwarding stops but the client stream is
    // still read until the client closes it, so the observation stays complete.
    // The read loop terminates only after every delivered byte has been read
    // (FIN returns -1; a reset throws after the buffer drains), which is why
    // connect() treats natural pump termination as "fully drained".
    private static void pumpClientToServer(Socket from, Socket to, Result result) {
        RecordScanner scanner = new RecordScanner();
        boolean forward = true;
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                scanner.scan(buf, n);
                if (scanner.sawClientKeyExchange) {
                    result.clientKeyExchangeSent = true;
                }
                if (forward) {
                    try {
                        out.write(buf, 0, n);
                        out.flush();
                    } catch (IOException broken) {
                        forward = false;   // keep scanning the client stream
                    }
                }
            }
        } catch (IOException endOfStream) {
            // Reset-on-close after the buffer was drained: the stream has still
            // been fully scanned. Natural termination is what connect() checks.
        }
        // NB: this pump never closes the shared sockets. Only the coordinator
        // in connect() closes them, and only after c2s has terminated, so a
        // pump exit can never cut short the other pump's read.
    }

    // server -> client: optionally drop or corrupt the ServerKeyExchange.
    // Crucially, this pump must NOT close the shared downstream socket on exit:
    // c2s reads from that same socket, and closing it here would truncate the
    // client->server scan and defeat the drain barrier. On exit we only
    // half-close the write direction (shutdownOutput) to propagate the server's
    // EOF to the client, leaving c2s's read direction intact. The coordinator
    // closes the sockets once c2s has drained.
    private static void pumpServerToClient(Socket from, Socket to, RecordRewriter rewriter) {
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                byte[] outBytes;
                if (rewriter.tamper == Tamper.NONE) {
                    outBytes = java.util.Arrays.copyOf(buf, n);
                } else {
                    outBytes = rewriter.feed(buf, n);
                }
                if (outBytes.length > 0) {
                    out.write(outBytes);
                    out.flush();
                }
            }
        } catch (Exception ignored) {
            // server side broke; fall through to the half-close below
        } finally {
            shutdownOutputQuietly(to);   // propagate EOF, keep read side open
        }
    }

    private static void shutdownOutputQuietly(Socket s) {
        try {
            if (!s.isClosed() && !s.isOutputShutdown()) {
                s.shutdownOutput();
            }
        } catch (Exception ignored) {
        }
    }

    // Lightweight read-only scanner for the client->server plaintext handshake
    // records (everything before ChangeCipherSpec is plaintext in TLCP 1.1).
    private static final class RecordScanner {
        private final ByteArrayOutputStream recordBuf = new ByteArrayOutputStream();
        private final ByteArrayOutputStream hsBuf = new ByteArrayOutputStream();
        private boolean raw = false;
        boolean sawClientKeyExchange = false;
        int alertDescription = -1;

        void scan(byte[] data, int len) {
            if (raw) {
                return;
            }
            recordBuf.write(data, 0, len);
            while (!raw) {
                byte[] all = recordBuf.toByteArray();
                if (all.length < 5) {
                    break;
                }
                int type = all[0] & 0xFF;
                int recLen = ((all[3] & 0xFF) << 8) | (all[4] & 0xFF);
                if (all.length < 5 + recLen) {
                    break;
                }
                if (type == 20) {               // ChangeCipherSpec -> ciphertext
                    raw = true;
                    break;
                }
                if (type == 22) {               // handshake
                    hsBuf.write(all, 5, recLen);
                    drainHandshake();
                } else if (type == 21 && recLen == 2) {     // plaintext alert
                    alertDescription = all[6] & 0xFF;
                }
                byte[] rest = new byte[all.length - 5 - recLen];
                System.arraycopy(all, 5 + recLen, rest, 0, rest.length);
                recordBuf.reset();
                recordBuf.write(rest, 0, rest.length);
            }
        }

        private void drainHandshake() {
            while (true) {
                byte[] hb = hsBuf.toByteArray();
                if (hb.length < 4) {
                    break;
                }
                int msgType = hb[0] & 0xFF;
                int msgLen = ((hb[1] & 0xFF) << 16)
                        | ((hb[2] & 0xFF) << 8) | (hb[3] & 0xFF);
                if (hb.length < 4 + msgLen) {
                    break;
                }
                if (msgType == 16) {            // ClientKeyExchange
                    sawClientKeyExchange = true;
                }
                byte[] rest = new byte[hb.length - 4 - msgLen];
                System.arraycopy(hb, 4 + msgLen, rest, 0, rest.length);
                hsBuf.reset();
                hsBuf.write(rest, 0, rest.length);
            }
        }
    }

    // Record rewriter for the server->client direction: reassembles handshake
    // messages across record boundaries and drops/corrupts the SKE (type 12).
    private static final class RecordRewriter {
        final Tamper tamper;
        private final ByteArrayOutputStream recordBuf = new ByteArrayOutputStream();
        private final ByteArrayOutputStream hsBuf = new ByteArrayOutputStream();
        private boolean raw = false;
        private int verHi = 0x01;
        private int verLo = 0x01;
        volatile int droppedSke = 0;
        volatile int corruptedSke = 0;

        RecordRewriter(Tamper tamper) {
            this.tamper = tamper;
        }

        byte[] feed(byte[] data, int len) {
            ByteArrayOutputStream outRecords = new ByteArrayOutputStream();
            if (raw) {
                outRecords.write(data, 0, len);
                return outRecords.toByteArray();
            }
            recordBuf.write(data, 0, len);
            while (!raw) {
                byte[] all = recordBuf.toByteArray();
                if (all.length < 5) {
                    break;
                }
                int type = all[0] & 0xFF;
                verHi = all[1] & 0xFF;
                verLo = all[2] & 0xFF;
                int recLen = ((all[3] & 0xFF) << 8) | (all[4] & 0xFF);
                if (all.length < 5 + recLen) {
                    break;
                }
                byte[] body = new byte[recLen];
                System.arraycopy(all, 5, body, 0, recLen);
                byte[] rest = new byte[all.length - 5 - recLen];
                System.arraycopy(all, 5 + recLen, rest, 0, rest.length);
                recordBuf.reset();
                recordBuf.write(rest, 0, rest.length);

                if (type == 20) {               // ChangeCipherSpec
                    writeRecord(outRecords, type, body);
                    raw = true;
                    break;
                }
                if (type == 22) {               // handshake
                    byte[] emitted = rewriteHandshake(body);
                    if (emitted.length > 0) {
                        writeRecord(outRecords, type, emitted);
                    }
                } else {
                    writeRecord(outRecords, type, body);
                }
            }
            return outRecords.toByteArray();
        }

        private byte[] rewriteHandshake(byte[] body) {
            hsBuf.write(body, 0, body.length);
            ByteArrayOutputStream emitted = new ByteArrayOutputStream();
            while (true) {
                byte[] hb = hsBuf.toByteArray();
                if (hb.length < 4) {
                    break;
                }
                int msgType = hb[0] & 0xFF;
                int msgLen = ((hb[1] & 0xFF) << 16)
                        | ((hb[2] & 0xFF) << 8) | (hb[3] & 0xFF);
                if (hb.length < 4 + msgLen) {
                    break;
                }
                byte[] msg = new byte[4 + msgLen];
                System.arraycopy(hb, 0, msg, 0, 4 + msgLen);
                byte[] rest = new byte[hb.length - 4 - msgLen];
                System.arraycopy(hb, 4 + msgLen, rest, 0, rest.length);
                hsBuf.reset();
                hsBuf.write(rest, 0, rest.length);

                if (msgType == 12) {            // ServerKeyExchange
                    if (tamper == Tamper.DROP_SKE) {
                        droppedSke++;
                        continue;               // vanish from the stream
                    }
                    if (tamper == Tamper.CORRUPT_SKE_SIG && msg.length > 4) {
                        // Flip the last byte, which lies within the trailing
                        // signature, invalidating it while keeping the framing.
                        msg[msg.length - 1] ^= 0x55;
                        corruptedSke++;
                    }
                }
                emitted.write(msg, 0, msg.length);
            }
            return emitted.toByteArray();
        }

        private void writeRecord(ByteArrayOutputStream out, int type, byte[] body) {
            out.write(type);
            out.write(verHi);
            out.write(verLo);
            out.write((body.length >> 8) & 0xFF);
            out.write(body.length & 0xFF);
            out.write(body, 0, body.length);
        }
    }
}
