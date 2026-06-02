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

package com.tencent.kona.ssl.misc;

import com.tencent.kona.ssl.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.util.Arrays;
import java.util.List;

/**
 * Regression test for the supported-protocol set of TLCP SSLContexts.
 * <pre>
 * TLCP11Context (and TLCPContext) used to inherit
 * AbstractTLSContext.getSupportedProtocolVersions(), which only
 * reports the standard TLS/SSL protocols. As a result,
 * SSLEngine#getSupportedProtocols() did not include "TLCPv1.1",
 * which broke strict frameworks (e.g. Spring Boot 3 / Kafka client
 * on JDK 17) that cross-check enabled vs. supported and threw
 * SSLHandshakeException: No appropriate protocol.
 * </pre>
 *
 * <p>This test asserts the supported protocol/cipher-suite sets exposed
 * by SSLEngine, SSLSocket and SSLServerSocket created from the
 * TLCPv1.1 and TLCP SSLContexts include TLCPv1.1 and at least one
 * TLCP_* cipher suite, and that calling
 * {@code setEnabledProtocols(new String[]{"TLCPv1.1"})} no longer
 * throws.</p>
 */
public class SupportedProtocolsTest {

    private static final String TLCP11 = "TLCPv1.1";
    private static final String TLCP_CIPHER_PREFIX = "TLCP_";

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testTLCP11ContextSSLEngineSupportedProtocols() throws Exception {
        SSLContext context = SSLContext.getInstance(TLCP11, TestUtils.PROVIDER);
        context.init(null, null, null);

        SSLEngine engine = context.createSSLEngine();
        List<String> supported = Arrays.asList(engine.getSupportedProtocols());
        Assertions.assertTrue(supported.contains(TLCP11),
                "TLCPv1.1 SSLEngine.getSupportedProtocols() should contain "
                        + TLCP11 + ", got " + supported);

        // Default-enabled protocols must be exactly TLCPv1.1 (i.e. they
        // must be a subset of the supported set we just asserted).
        List<String> enabled = Arrays.asList(engine.getEnabledProtocols());
        Assertions.assertTrue(supported.containsAll(enabled),
                "Enabled " + enabled + " must be a subset of supported "
                        + supported);
    }

    @Test
    public void testTLCP11ContextSSLEngineSupportedCipherSuites()
            throws Exception {
        SSLContext context = SSLContext.getInstance(TLCP11, TestUtils.PROVIDER);
        context.init(null, null, null);

        SSLEngine engine = context.createSSLEngine();
        List<String> supportedCS = Arrays.asList(engine.getSupportedCipherSuites());
        Assertions.assertTrue(
                supportedCS.stream().anyMatch(s -> s.startsWith(TLCP_CIPHER_PREFIX)),
                "TLCPv1.1 SSLEngine.getSupportedCipherSuites() should contain "
                        + "at least one TLCP_* cipher suite, got " + supportedCS);
    }

    @Test
    public void testTLCP11ContextSetEnabledTLCPv11() throws Exception {
        SSLContext context = SSLContext.getInstance(TLCP11, TestUtils.PROVIDER);
        context.init(null, null, null);

        // The pre-fix behaviour was that explicitly setting TLCPv1.1 here
        // (or having a framework do so) would later cause JSSE / engine
        // initialisation to throw because TLCPv1.1 was not in the
        // supported set. After the fix, this is a no-op assignment.
        SSLEngine engine = context.createSSLEngine();
        engine.setEnabledProtocols(new String[] { TLCP11 });
        Assertions.assertArrayEquals(new String[] { TLCP11 },
                engine.getEnabledProtocols());
    }

    @Test
    public void testTLCP11ContextSocketFactoriesSupportedProtocols()
            throws Exception {
        SSLContext context = SSLContext.getInstance(TLCP11, TestUtils.PROVIDER);
        context.init(null, null, null);

        SSLSocketFactory ssf = context.getSocketFactory();
        SSLSocket clientSocket = (SSLSocket) ssf.createSocket();
        try {
            List<String> supported = Arrays.asList(
                    clientSocket.getSupportedProtocols());
            Assertions.assertTrue(supported.contains(TLCP11),
                    "TLCPv1.1 SSLSocket.getSupportedProtocols() should contain "
                            + TLCP11 + ", got " + supported);
        } finally {
            clientSocket.close();
        }

        SSLServerSocketFactory sssf = context.getServerSocketFactory();
        try (java.net.ServerSocket serverSocket = sssf.createServerSocket()) {
            List<String> supported = Arrays.asList(
                    ((javax.net.ssl.SSLServerSocket) serverSocket)
                            .getSupportedProtocols());
            Assertions.assertTrue(supported.contains(TLCP11),
                    "TLCPv1.1 SSLServerSocket.getSupportedProtocols() should "
                            + "contain " + TLCP11 + ", got " + supported);
        }
    }

    @Test
    public void testTLCPContextSupportedProtocolsAndCipherSuites()
            throws Exception {
        SSLContext context = SSLContext.getInstance("TLCP", TestUtils.PROVIDER);
        context.init(null, null, null);

        SSLEngine engine = context.createSSLEngine();
        List<String> supported = Arrays.asList(engine.getSupportedProtocols());
        // The TLCP context must support both TLCPv1.1 and the standard
        // TLS protocols it can fall back to.
        Assertions.assertTrue(supported.contains(TLCP11),
                "TLCP SSLEngine.getSupportedProtocols() should contain "
                        + TLCP11 + ", got " + supported);
        Assertions.assertTrue(supported.contains("TLSv1.2"),
                "TLCP SSLEngine.getSupportedProtocols() should contain "
                        + "TLSv1.2, got " + supported);
        Assertions.assertTrue(supported.contains("TLSv1.3"),
                "TLCP SSLEngine.getSupportedProtocols() should contain "
                        + "TLSv1.3, got " + supported);

        List<String> supportedCS = Arrays.asList(engine.getSupportedCipherSuites());
        Assertions.assertTrue(
                supportedCS.stream().anyMatch(s -> s.startsWith(TLCP_CIPHER_PREFIX)),
                "TLCP SSLEngine.getSupportedCipherSuites() should contain "
                        + "at least one TLCP_* cipher suite, got " + supportedCS);
    }
}
