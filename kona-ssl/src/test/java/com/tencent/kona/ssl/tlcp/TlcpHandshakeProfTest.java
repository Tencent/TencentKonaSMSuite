/*
 * Copyright (c) 2022, Oracle and/or its affiliates. All rights reserved.
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

package com.tencent.kona.ssl.tlcp;

import com.tencent.kona.ssl.TestUtils;
import com.tencent.kona.ssl.interop.ContextProtocol;
import com.tencent.kona.ssl.interop.Provider;
import com.tencent.kona.ssl.interop.SmCertTuple;
import com.tencent.kona.ssl.interop.Utilities;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLSession;
import java.nio.ByteBuffer;

import static com.tencent.kona.ssl.tlcp.TlcpUtils.CLIENT_ENC_CERT;
import static com.tencent.kona.ssl.tlcp.TlcpUtils.CLIENT_SIGN_CERT;
import static com.tencent.kona.ssl.tlcp.TlcpUtils.INTCA_CERT;
import static com.tencent.kona.ssl.tlcp.TlcpUtils.SERVER_ENC_CERT;
import static com.tencent.kona.ssl.tlcp.TlcpUtils.SERVER_SIGN_CERT;

public class TlcpHandshakeProfTest {

    private static final SmCertTuple SERVER_CERT_TUPLE
            = new SmCertTuple(INTCA_CERT, SERVER_SIGN_CERT, SERVER_ENC_CERT);
    private static final SmCertTuple CLIENT_CERT_TUPLE
            = new SmCertTuple(INTCA_CERT, CLIENT_SIGN_CERT, CLIENT_ENC_CERT);

    static {
        TestUtils.addProviders();
    }

    private SSLContext serverContext;
    private SSLContext clientContext;

    private SSLEngine clientEngine;
    private ByteBuffer clientOut = ByteBuffer.allocate(5);
    private ByteBuffer clientIn = ByteBuffer.allocate(1 << 15);

    private SSLEngine serverEngine;
    private ByteBuffer serverOut = ByteBuffer.allocate(5);
    private ByteBuffer serverIn = ByteBuffer.allocate(1 << 15);

    private ByteBuffer cTOs = ByteBuffer.allocateDirect(1 << 16);
    private ByteBuffer sTOc = ByteBuffer.allocateDirect(1 << 16);

    boolean resume = false;

    public static void main(String[] args) throws Exception {
        TlcpHandshakeProfTest test = new TlcpHandshakeProfTest();
        test.init();

        for (int i = 0; i < 1_000_000_000; i++) {
            test.doHandshake();
        }
    }

    public void init() throws Exception {
        serverContext = Utilities.createSSLContext(Provider.KONA,
                ContextProtocol.TLCP11, SERVER_CERT_TUPLE);
        clientContext = Utilities.createSSLContext(Provider.KONA,
                ContextProtocol.TLCP11, CLIENT_CERT_TUPLE);
    }

    /**
     * This benchmark measures the time needed to perform a TLS handshake.
     * Data is exchanged using a pair of ByteBuffers.
     * The client and the server both operate on the same thread.
     */
    public SSLSession doHandshake() throws Exception {
        createSSLEngines();

        boolean isCtoS = true;
        for (;;) {
            HandshakeStatus result;
            if (isCtoS) {
                result = checkResult(clientEngine,
                        clientEngine.wrap(clientOut, cTOs));
                cTOs.flip();
                checkResult(serverEngine, serverEngine.unwrap(cTOs, serverIn));
                cTOs.compact();
                if (result == HandshakeStatus.NEED_UNWRAP) {
                    isCtoS = false;
                } else if (result == HandshakeStatus.FINISHED) {
                    break;
                } else if (result != HandshakeStatus.NEED_WRAP) {
                    throw new Exception("Unexpected result "+result);
                }
            } else {
                result = checkResult(serverEngine,
                        serverEngine.wrap(serverOut, sTOc));
                sTOc.flip();
                checkResult(clientEngine,
                        clientEngine.unwrap(sTOc, clientIn));
                sTOc.compact();
                if (result == HandshakeStatus.NEED_UNWRAP) {
                    isCtoS = true;
                } else if (result == HandshakeStatus.FINISHED) {
                    break;
                } else if (result != HandshakeStatus.NEED_WRAP) {
                    throw new Exception("Unexpected result "+result);
                }
            }
        }

        SSLSession session = clientEngine.getSession();
        if (resume) {
            // TLS 1.3 needs another wrap/unwrap to deliver a session ticket
            serverEngine.wrap(serverOut, sTOc);
            sTOc.flip();
            clientEngine.unwrap(sTOc, clientIn);
            sTOc.compact();
        } else {
            // invalidate TLS1.2 session. TLS 1.3 doesn't care
            session.invalidate();
        }
        return session;
    }

    private void createSSLEngines() {
        /*
         * Configure the serverEngine to act as a server in the SSL/TLS
         * handshake.
         */
        serverEngine = serverContext.createSSLEngine();
        serverEngine.setUseClientMode(false);

        /*
         * Similar to above, but using client mode instead.
         */
        clientEngine = clientContext.createSSLEngine("client", 80);
        clientEngine.setUseClientMode(true);
        clientEngine.setEnabledProtocols(new String[] {"TLCPv1.1"});
        clientEngine.setEnabledCipherSuites(new String[] { "TLCP_ECC_SM4_GCM_SM3" });
    }

    private HandshakeStatus checkResult(SSLEngine engine, SSLEngineResult result) {
        HandshakeStatus hsStatus = result.getHandshakeStatus();

        if (hsStatus == HandshakeStatus.NEED_TASK) {
            Runnable runnable;
            while ((runnable = engine.getDelegatedTask()) != null) {
                runnable.run();
            }
            hsStatus = engine.getHandshakeStatus();
        }
        return hsStatus;
    }
}
