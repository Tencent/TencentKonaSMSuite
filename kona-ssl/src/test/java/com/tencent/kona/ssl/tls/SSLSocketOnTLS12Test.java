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

/*
 * @test
 * @bug 8161106 8170329
 * @modules jdk.crypto.ec
 * @summary Improve SSLSocket test template
 * @run main/othervm SSLSocketTemplate
 */

package com.tencent.kona.ssl.tls;

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.pkix.PKIXInsts;
import com.tencent.kona.ssl.SSLInsts;
import com.tencent.kona.ssl.TestUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Template to help speed your client/server tests.
 *
 * Two examples that use this template:
 * test/jdk/sun/security/ssl/ServerHandshaker/AnonCipherWithWantClientAuth.java
 * test/jdk/sun/net/www/protocol/https/HttpsClient/ServerIdentityTest.java
 */
public class SSLSocketOnTLS12Test {

    @BeforeAll
    public static void setup() {
//        System.setProperty("com.tencent.kona.ssl.debug", "all");
        System.setProperty("com.tencent.kona.ssl.namedGroups", "curveSM2");
        System.setProperty("com.tencent.kona.ssl.client.signatureSchemes", "sm2sig_sm3");
        TestUtils.addProviders();
    }

    /*
     * ==================
     * Run the test case.
     */
    @Test
    public void testSSL() throws Exception {
        run();
    }

    /*
     * Run the test case.
     */
    public void run() throws Exception {
        bootup();
    }

    /*
     * Define the server side application of the test for the specified socket.
     */
    protected void runServerApplication(SSLSocket socket) throws Exception {
        // here comes the test logic
        InputStream sslIS = socket.getInputStream();
        OutputStream sslOS = socket.getOutputStream();

        sslIS.read();
        sslOS.write(85);
        sslOS.flush();
    }

    /*
     * Define the client side application of the test for the specified socket.
     * This method is used if the returned value of
     * isCustomizedClientConnection() is false.
     *
     * @param socket may be null is no client socket is generated.
     *
     * @see #isCustomizedClientConnection()
     */
    protected void runClientApplication(SSLSocket socket) throws Exception {
        InputStream sslIS = socket.getInputStream();
        OutputStream sslOS = socket.getOutputStream();

        sslOS.write(280);
        sslOS.flush();
        sslIS.read();
    }

    /*
     * Define the client side application of the test for the specified
     * server port.  This method is used if the returned value of
     * isCustomizedClientConnection() is true.
     *
     * Note that the client need to connect to the server port by itself
     * for the actual message exchange.
     *
     * @see #isCustomizedClientConnection()
     */
    protected void runClientApplication(int serverPort) throws Exception {
        // blank
    }

    /*
     * Create an instance of SSLContext for client use.
     */
    protected SSLContext createClientSSLContext() throws Exception {
        return createSSLContext(TRUSTED_CERTS, END_ENTITY_CERTS,
                getClientContextParameters());
    }

    /*
     * Create an instance of SSLContext for server use.
     */
    protected SSLContext createServerSSLContext() throws Exception {
        return createSSLContext(TRUSTED_CERTS, END_ENTITY_CERTS,
                getServerContextParameters());
    }

    /*
     * The parameters used to configure SSLContext.
     */
    protected static final class ContextParameters {
        final String contextProtocol;
        final String tmAlgorithm;
        final String kmAlgorithm;

        ContextParameters(String contextProtocol,
                String tmAlgorithm, String kmAlgorithm) {

            this.contextProtocol = contextProtocol;
            this.tmAlgorithm = tmAlgorithm;
            this.kmAlgorithm = kmAlgorithm;
        }
    }

    /*
     * Get the client side parameters of SSLContext.
     */
    protected ContextParameters getClientContextParameters() {
        return new ContextParameters("TLS", "PKIX", "NewSunX509");
    }

    /*
     * Get the server side parameters of SSLContext.
     */
    protected ContextParameters getServerContextParameters() {
        return new ContextParameters("TLS", "PKIX", "NewSunX509");
    }

    /*
     * Does the client side use customized connection other than
     * explicit Socket.connect(), for example, URL.openConnection()?
     */
    protected boolean isCustomizedClientConnection() {
        return false;
    }

    /*
     * Configure the client side socket.
     */
    protected void configureClientSocket(SSLSocket socket) {
        socket.setEnabledProtocols(new String[] { "TLSv1.2" });
    }

    /*
     * Configure the server side socket.
     */
    protected void configureServerSocket(SSLServerSocket socket) {
        socket.setNeedClientAuth(true);
    }

    /*
     * =============================================
     * Define the client and server side operations.
     *
     * If the client or server is doing some kind of object creation
     * that the other side depends on, and that thread prematurely
     * exits, you may experience a hang.  The test harness will
     * terminate all hung threads after its timeout has expired,
     * currently 3 minutes by default, but you might try to be
     * smart about it....
     */

    /*
     * Is the server ready to serve?
     */
    protected final CountDownLatch serverCondition = new CountDownLatch(1);

    /*
     * Is the client ready to handshake?
     */
    protected final CountDownLatch clientCondition = new CountDownLatch(1);

    /*
     * What's the server port?  Use any free port by default
     */
    protected volatile int serverPort = 0;

    /*
     * What's the server address?  null means binding to the wildcard.
     */
    protected volatile InetAddress serverAddress = null;

    /*
     * Define the server side of the test.
     */
    protected void doServerSide() throws Exception {
        // kick start the server side service
        SSLContext context = createServerSSLContext();
        SSLServerSocketFactory sslssf = context.getServerSocketFactory();
        InetAddress serverAddress = this.serverAddress;
        SSLServerSocket sslServerSocket = serverAddress == null ?
                (SSLServerSocket)sslssf.createServerSocket(serverPort)
                : (SSLServerSocket)sslssf.createServerSocket();
        if (serverAddress != null) {
            sslServerSocket.bind(new InetSocketAddress(serverAddress, serverPort));
        }
        configureServerSocket(sslServerSocket);
        serverPort = sslServerSocket.getLocalPort();

        // Signal the client, the server is ready to accept connection.
        serverCondition.countDown();

        // Try to accept a connection in 30 seconds.
        SSLSocket sslSocket;
        try {
            sslServerSocket.setSoTimeout(300000);
            sslSocket = (SSLSocket)sslServerSocket.accept();
        } catch (SocketTimeoutException ste) {
            // Ignore the test case if no connection within 30 seconds.
            System.out.println(
                "No incoming client connection in 30 seconds. " +
                "Ignore in server side.");
            return;
        } finally {
            sslServerSocket.close();
        }

        // handle the connection
        try {
            // Is it the expected client connection?
            //
            // Naughty test cases or third party routines may try to
            // connection to this server port unintentionally.  In
            // order to mitigate the impact of unexpected client
            // connections and avoid intermittent failure, it should
            // be checked that the accepted connection is really linked
            // to the expected client.
            boolean clientIsReady =
                    clientCondition.await(30L, TimeUnit.SECONDS);

            if (clientIsReady) {
                // Run the application in server side.
                runServerApplication(sslSocket);
            } else {    // Otherwise, ignore
                // We don't actually care about plain socket connections
                // for TLS communication testing generally.  Just ignore
                // the test if the accepted connection is not linked to
                // the expected client or the client connection timeout
                // in 30 seconds.
                System.out.println(
                        "The client is not the expected one or timeout. " +
                        "Ignore in server side.");
            }
        } finally {
            sslSocket.close();
        }
    }

    /*
     * Define the client side of the test.
     */
    protected void doClientSide() throws Exception {

        // Wait for server to get started.
        //
        // The server side takes care of the issue if the server cannot
        // get started in 90 seconds.  The client side would just ignore
        // the test case if the serer is not ready.
        boolean serverIsReady =
                serverCondition.await(90L, TimeUnit.SECONDS);
        if (!serverIsReady) {
            System.out.println(
                    "The server is not ready yet in 90 seconds. " +
                    "Ignore in client side.");
            return;
        }

        if (isCustomizedClientConnection()) {
            // Signal the server, the client is ready to communicate.
            clientCondition.countDown();

            // Run the application in client side.
            runClientApplication(serverPort);

            return;
        }

        SSLContext context = createClientSSLContext();
        SSLSocketFactory sslsf = context.getSocketFactory();

        try (SSLSocket sslSocket = (SSLSocket)sslsf.createSocket()) {
            try {
                configureClientSocket(sslSocket);
                InetAddress serverAddress = this.serverAddress;
                InetSocketAddress connectAddress = serverAddress == null
                        ? new InetSocketAddress("localhost", serverPort)
                        : new InetSocketAddress(serverAddress, serverPort);
                sslSocket.connect(connectAddress, 15000);
            } catch (IOException ioe) {
                // The server side may be impacted by naughty test cases or
                // third party routines, and cannot accept connections.
                //
                // Just ignore the test if the connection cannot be
                // established.
                System.out.println(
                        "Cannot make a connection in 15 seconds. " +
                        "Ignore in client side.");
                return;
            }

            // OK, here the client and server get connected.

            // Signal the server, the client is ready to communicate.
            clientCondition.countDown();

            // There is still a chance in theory that the server thread may
            // wait client-ready timeout and then quit.  The chance should
            // be really rare so we don't consider it until it becomes a
            // real problem.

            // Run the application in client side.
            runClientApplication(sslSocket);
        }
    }

    /*
     * =============================================
     * Stuffs to customize the SSLContext instances.
     */

    /*
     * =======================================
     * Certificates and keys used in the test.
     */
    // Trusted certificates.
    protected final static Cert[] TRUSTED_CERTS = {
            Cert.CA_SM2_CURVESM2 };

    // End entity certificate.
    protected final static Cert[] END_ENTITY_CERTS = {
            Cert.EE_SM2_CURVESM2 };

    /*
     * Create an instance of SSLContext with the specified trust/key materials.
     */
    public static SSLContext createSSLContext(
            Cert[] trustedCerts,
            Cert[] endEntityCerts,
            ContextParameters params) throws Exception {

        KeyStore ts = null;     // trust store
        KeyStore ks = null;     // key store
        char passphrase[] = "passphrase".toCharArray();

        // Generate certificate from cert string.
        CertificateFactory cf = PKIXInsts.getCertificateFactory("X.509");

        // Import the trused certs.
        ByteArrayInputStream is;
        if (trustedCerts != null && trustedCerts.length != 0) {
            ts = PKIXInsts.getKeyStore("PKCS12");
            ts.load(null, null);

            Certificate[] trustedCert = new Certificate[trustedCerts.length];
            for (int i = 0; i < trustedCerts.length; i++) {
                is = new ByteArrayInputStream(trustedCerts[i].certStr.getBytes());
                try {
                    trustedCert[i] = cf.generateCertificate(is);
                } finally {
                    is.close();
                }

                ts.setCertificateEntry(
                        "trusted-cert-" + trustedCerts[i].name(), trustedCert[i]);
            }
        }

        // Import the key materials.
        if (endEntityCerts != null && endEntityCerts.length != 0) {
            ks = PKIXInsts.getKeyStore("PKCS12");
            ks.load(null, null);

            for (int i = 0; i < endEntityCerts.length; i++) {
                // generate the private key.
                PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(
                    Base64.getMimeDecoder().decode(endEntityCerts[i].privKeyStr));
                KeyFactory kf = CryptoInsts.getKeyFactory(
                        endEntityCerts[i].keyAlgo);
                PrivateKey priKey = kf.generatePrivate(priKeySpec);

                // generate certificate chain
                is = new ByteArrayInputStream(
                        endEntityCerts[i].certStr.getBytes());
                Certificate keyCert = null;
                try {
                    keyCert = cf.generateCertificate(is);
                } finally {
                    is.close();
                }

                Certificate[] chain = new Certificate[] { keyCert };

                // import the key entry.
                ks.setKeyEntry("cert-" + endEntityCerts[i].name(),
                        priKey, passphrase, chain);
            }
        }

        // Create an SSLContext object.
        TrustManagerFactory tmf =
                SSLInsts.getTrustManagerFactory(params.tmAlgorithm);
        tmf.init(ts);

        SSLContext context = SSLInsts.getSSLContext(params.contextProtocol);
        if (endEntityCerts != null && endEntityCerts.length != 0 && ks != null) {
            KeyManagerFactory kmf =
                    SSLInsts.getKeyManagerFactory(params.kmAlgorithm);
            kmf.init(ks, passphrase);

            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        } else {
            context.init(null, tmf.getTrustManagers(), null);
        }

        return context;
    }

    /*
     * =================================================
     * Stuffs to boot up the client-server mode testing.
     */
    private Thread clientThread = null;
    private Thread serverThread = null;
    private volatile Exception serverException = null;
    private volatile Exception clientException = null;

    /*
     * Should we run the client or server in a separate thread?
     * Both sides can throw exceptions, but do you have a preference
     * as to which side should be the main thread.
     */
    private final boolean separateServerThread = false;

    /*
     * Boot up the testing, used to drive remainder of the test.
     */
    private void bootup() throws Exception {
        Exception startException = null;
        try {
            if (separateServerThread) {
                startServer(true);
                startClient(false);
            } else {
                startClient(true);
                startServer(false);
            }
        } catch (Exception e) {
            startException = e;
        }

        /*
         * Wait for other side to close down.
         */
        if (separateServerThread) {
            if (serverThread != null) {
                serverThread.join();
            }
        } else {
            if (clientThread != null) {
                clientThread.join();
            }
        }

        /*
         * When we get here, the test is pretty much over.
         * Which side threw the error?
         */
        Exception local;
        Exception remote;

        if (separateServerThread) {
            remote = serverException;
            local = clientException;
        } else {
            remote = clientException;
            local = serverException;
        }

        Exception exception = null;

        /*
         * Check various exception conditions.
         */
        if ((local != null) && (remote != null)) {
            // If both failed, return the curthread's exception.
            local.initCause(remote);
            exception = local;
        } else if (local != null) {
            exception = local;
        } else if (remote != null) {
            exception = remote;
        } else if (startException != null) {
            exception = startException;
        }

        /*
         * If there was an exception *AND* a startException,
         * output it.
         */
        if (exception != null) {
            if (exception != startException && startException != null) {
                exception.addSuppressed(startException);
            }
            throw exception;
        }

        // Fall-through: no exception to throw!
    }

    private void startServer(boolean newThread) throws Exception {
        if (newThread) {
            serverThread = new Thread() {
                @Override
                public void run() {
                    try {
                        doServerSide();
                    } catch (Exception e) {
                        /*
                         * Our server thread just died.
                         *
                         * Release the client, if not active already...
                         */
                        logException("Server died", e);
                        serverException = e;
                    }
                }
            };
            serverThread.start();
        } else {
            try {
                doServerSide();
            } catch (Exception e) {
                logException("Server failed", e);
                serverException = e;
            }
        }
    }

    private void startClient(boolean newThread) throws Exception {
        if (newThread) {
            clientThread = new Thread() {
                @Override
                public void run() {
                    try {
                        doClientSide();
                    } catch (Exception e) {
                        /*
                         * Our client thread just died.
                         */
                        logException("Client died", e);
                        clientException = e;
                    }
                }
            };
            clientThread.start();
        } else {
            try {
                doClientSide();
            } catch (Exception e) {
                logException("Client failed", e);
                clientException = e;
            }
        }
    }

    private synchronized void logException(String prefix, Throwable cause) {
        System.out.println(prefix + ": " + cause);
        cause.printStackTrace(System.out);
    }

    public static enum Cert {

        CA_SM2_CURVESM2(
                "EC",
                // SM3withSM2, curve curveSM2
                // Validity
                //     Not Before: Sep 11 20:15:16 2021 GMT
                //     Not After : Sep  9 20:15:16 2031 GMT
                // Subject Key Identifier:
                //     BD:AA:64:6D:4D:40:33:81:B7:50:B3:4D:2F:12:7D:8E:A6:EF:64:42
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIBrzCCAVWgAwIBAgIUZrPwF3PqWGDcrhVbe8rX4DwJmEUwCgYIKoEcz1UBg3Uw\n" +
                "FDESMBAGA1UEAwwJY2Etc20yc20yMB4XDTIxMDkxMTIwMTUxNloXDTMxMDkwOTIw\n" +
                "MTUxNlowHjEcMBoGA1UEAwwTaW50Y2Etc20yc20yLXNtMnNtMjBZMBMGByqGSM49\n" +
                "AgEGCCqBHM9VAYItA0IABGLX296HPUZRxCUA0wto7flk/+Rim4CF+2r4wz9LOOVy\n" +
                "XJK42DMPn1DaU5NSBtLmkPKuVcjBQE9QF6S44nu6j2SjezB5MB0GA1UdDgQWBBS9\n" +
                "qmRtTUAzgbdQs00vEn2Opu9kQjAfBgNVHSMEGDAWgBQKYcEi1iAGgEhoipbvCEd1\n" +
                "/zIBhDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAWBgNVHSUBAf8E\n" +
                "DDAKBggrBgEFBQcDCTAKBggqgRzPVQGDdQNIADBFAiBhZ2wnl2uyKbvU2dJL31F1\n" +
                "6aSMTWpH3VqAhw7iPmXKPAIhAOuHJmkcFAv/QzIWHb0hs7WN/t3srddg/8JDd4ee\n" +
                "Y7QW\n" +
                "-----END CERTIFICATE-----",
                "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKWfrthUXfdgXGGI9\n" +
                "qBJO/uIvABG6E4gcq/vMeGldll+hRANCAARi19vehz1GUcQlANMLaO35ZP/kYpuA\n" +
                "hftq+MM/SzjlclySuNgzD59Q2lOTUgbS5pDyrlXIwUBPUBekuOJ7uo9k"),

        EE_SM2_CURVESM2(
                "EC",
                // SM3withSM2, curve curveSM2
                // Validity
                //     Not Before: Sep 11 20:15:16 2021 GMT
                //     Not After : Sep  9 20:15:16 2031 GMT
                // Authority Key Identifier:
                //     BD:AA:64:6D:4D:40:33:81:B7:50:B3:4D:2F:12:7D:8E:A6:EF:64:42
                "-----BEGIN CERTIFICATE-----\n" +
                "MIIBgzCCASqgAwIBAgIUD07zQtI4B+1/cKrD6QHItm42xiowCgYIKoEcz1UBg3Uw\n" +
                "HjEcMBoGA1UEAwwTaW50Y2Etc20yc20yLXNtMnNtMjAeFw0yMTA5MTEyMDE1MTZa\n" +
                "Fw0zMTA5MDkyMDE1MTZaMCIxIDAeBgNVBAMMF2VlLXNtMnNtMi1zbTJzbTItc20y\n" +
                "c20yMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEe5p0g94Tk/d/4zBEeZfxLpdO\n" +
                "2XAr7v2DNaTDhYtTPzqp68s3Uuo4UaQYpJZTAEjmC3PXjc4wTlEo9j7404MA5KNC\n" +
                "MEAwHQYDVR0OBBYEFNC9Z54XBny5TYlZ09VvFK0mXY5wMB8GA1UdIwQYMBaAFL2q\n" +
                "ZG1NQDOBt1CzTS8SfY6m72RCMAoGCCqBHM9VAYN1A0cAMEQCIF6MhaUpBiUGehLP\n" +
                "t1F8/sPA/D19wHXozn6cGKr0OdjZAiAKuqWu1zTwwLCEvc6RoCPdxC/M8JUh7to3\n" +
                "FS4Y9Dgshg==\n" +
                "-----END CERTIFICATE-----",
                "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgcl+HTIB9ylaqVCDS\n" +
                "F76T0zPnTZ7QI9SIBlw7ZU+GYb2hRANCAAR7mnSD3hOT93/jMER5l/Eul07ZcCvu\n" +
                "/YM1pMOFi1M/OqnryzdS6jhRpBikllMASOYLc9eNzjBOUSj2PvjTgwDk");

        final String keyAlgo;
        final String certStr;
        final String privKeyStr;

        Cert(String keyAlgo, String certStr, String privKeyStr) {
            this.keyAlgo = keyAlgo;
            this.certStr = certStr;
            this.privKeyStr = privKeyStr;
        }
    }
}
