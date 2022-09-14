package com.tencent.kona.ssl.tlcp;

import com.tencent.kona.ssl.interop.BabaSSLServer;
import com.tencent.kona.ssl.interop.CertTuple;
import com.tencent.kona.ssl.interop.CipherSuite;
import com.tencent.kona.ssl.interop.Client;
import com.tencent.kona.ssl.interop.ClientAuth;
import com.tencent.kona.ssl.interop.ContextProtocol;
import com.tencent.kona.ssl.interop.FileCert;
import com.tencent.kona.ssl.interop.JdkClient;
import com.tencent.kona.ssl.interop.Protocol;
import com.tencent.kona.ssl.interop.Server;
import com.tencent.kona.ssl.interop.ServerCaller;
import com.tencent.kona.ssl.interop.SmCertTuple;
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

import static com.tencent.kona.ssl.tlcp.TlcpUtils.CLIENT_CERT;
import static com.tencent.kona.ssl.tlcp.TlcpUtils.CLIENT_ENC_CERT;
import static com.tencent.kona.ssl.tlcp.TlcpUtils.CLIENT_SIGN_CERT;
import static com.tencent.kona.ssl.tlcp.TlcpUtils.INTCA_CERT;
import static com.tencent.kona.ssl.tlcp.TlcpUtils.SERVER_CERT;
import static com.tencent.kona.ssl.tlcp.TlcpUtils.SERVER_ENC_CERT;
import static com.tencent.kona.ssl.tlcp.TlcpUtils.SERVER_SIGN_CERT;

/**
 * The interop test between BabaSSL(OpenSSL) server and JDK client.
 */
public class BabaSSLServerJdkClientTest {

    private static final String PAGE_FILE_NAME = "tlcp-page";

    @BeforeAll
    public static void setup() throws IOException {
        TestUtils.addProviders();
        createWebPage();
    }

    private static void createWebPage() throws IOException {
        Files.write(Paths.get(PAGE_FILE_NAME),
                "BabaSSL server".getBytes(Utilities.CHARSET),
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
    public void testConnect() throws Exception {
        testConnect(ClientAuth.NONE);
        testConnectWithSingleCert(ClientAuth.NONE);
    }

    @Test
    public void testConnectWithClientAuth() throws Exception {
        testConnect(ClientAuth.REQUIRED);
        testConnectWithSingleCert(ClientAuth.REQUIRED);
    }

    private void testConnect(ClientAuth clientAuth) throws Exception {
        connect(INTCA_CERT,
                SERVER_SIGN_CERT, SERVER_ENC_CERT,
                CLIENT_SIGN_CERT, CLIENT_ENC_CERT,
                CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                clientAuth);
        connect(INTCA_CERT,
                SERVER_SIGN_CERT, SERVER_ENC_CERT,
                CLIENT_SIGN_CERT, CLIENT_ENC_CERT,
                CipherSuite.TLCP_ECC_SM4_GCM_SM3,
                clientAuth);
    }

    private void testConnectWithSingleCert(ClientAuth clientAuth) throws Exception {
        connect(INTCA_CERT,
                SERVER_CERT, null,
                CLIENT_CERT, null,
                CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                clientAuth);
        connect(INTCA_CERT,
                SERVER_CERT, null,
                CLIENT_CERT, null,
                CipherSuite.TLCP_ECC_SM4_GCM_SM3,
                clientAuth);
    }

    // When use ECDHE_ cipher suites,
    // the server requires client's certificates implicitly.
    @Test
    public void testConnectOnEphemeral() throws Exception {
        connect(INTCA_CERT,
                SERVER_SIGN_CERT, SERVER_ENC_CERT,
                CLIENT_SIGN_CERT, CLIENT_ENC_CERT,
                CipherSuite.TLCP_ECDHE_SM4_CBC_SM3,
                ClientAuth.REQUIRED);
        connect(INTCA_CERT,
                SERVER_SIGN_CERT, SERVER_ENC_CERT,
                CLIENT_SIGN_CERT, CLIENT_ENC_CERT,
                CipherSuite.TLCP_ECDHE_SM4_GCM_SM3,
                ClientAuth.REQUIRED);
    }

    private void connect(
            FileCert trustedCert,
            FileCert serverSignCert, FileCert serverEncCert,
            FileCert clientSignCert, FileCert clientEncCert,
            CipherSuite clientCipherSuite,
            ClientAuth clientAuth) throws Exception {
        SmCertTuple serverCertTuple = new SmCertTuple(
                trustedCert, serverSignCert, serverEncCert);
        SmCertTuple clientCertTuple = new SmCertTuple(
                trustedCert, clientSignCert, clientEncCert);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        BabaSSLServer.Builder serverBuilder = new BabaSSLServer.Builder();
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.setCipherSuites(
                CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                CipherSuite.TLCP_ECDHE_SM4_GCM_SM3,
                CipherSuite.TLCP_ECC_SM4_GCM_SM3,
                CipherSuite.TLCP_ECDHE_SM4_CBC_SM3);
        serverBuilder.setClientAuth(clientAuth);

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            try (Client client = createClientBuilder(
                    clientCertTuple, clientCipherSuite).build()) {
                client.connect("127.0.0.1", server.getPort());
            }
        } finally {
            executor.shutdown();
        }
    }

    @Test
    public void testALPN() throws Exception {
        testALPN(CipherSuite.TLCP_ECC_SM4_CBC_SM3, ClientAuth.NONE);
        testALPN(CipherSuite.TLCP_ECC_SM4_CBC_SM3, ClientAuth.REQUIRED);
        testALPN(CipherSuite.TLCP_ECC_SM4_GCM_SM3, ClientAuth.NONE);
        testALPN(CipherSuite.TLCP_ECC_SM4_GCM_SM3, ClientAuth.REQUIRED);
    }

    private void testALPN(CipherSuite clientCipherSuite, ClientAuth clientAuth)
            throws Exception {
        SmCertTuple certTuple = new SmCertTuple(
                INTCA_CERT, SERVER_SIGN_CERT, SERVER_ENC_CERT);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        BabaSSLServer.Builder serverBuilder = new BabaSSLServer.Builder();
        serverBuilder.setContextProtocol(ContextProtocol.TLCP11);
        serverBuilder.setCertTuple(certTuple);
        serverBuilder.setAppProtocols("HTTP/1.1", "h2");
        serverBuilder.setClientAuth(clientAuth);

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            JdkClient.Builder clientBuilder = createClientBuilder(
                    certTuple, clientCipherSuite);
            clientBuilder.setAppProtocols("h2");
            try (JdkClient client = clientBuilder.build()) {
                client.connect("127.0.0.1", server.getPort());
                Assertions.assertEquals("h2", client.getNegoAppProtocol());
            }
        } finally {
            executor.shutdown();
        }
    }

//    @Test
    // TODO BabaSSL s_server doesn't support the testing for SNI on TLCP yet.
    public void testSNI() throws Exception {
        testSNI(CipherSuite.TLCP_ECC_SM4_CBC_SM3, ClientAuth.NONE);
        testSNI(CipherSuite.TLCP_ECC_SM4_CBC_SM3, ClientAuth.REQUIRED);
        testSNI(CipherSuite.TLCP_ECC_SM4_GCM_SM3, ClientAuth.NONE);
        testSNI(CipherSuite.TLCP_ECC_SM4_GCM_SM3, ClientAuth.REQUIRED);
    }

    private void testSNI(CipherSuite clientCipherSuite, ClientAuth clientAuth)
            throws Exception {
        SmCertTuple certTuple = new SmCertTuple(
                INTCA_CERT, SERVER_SIGN_CERT, SERVER_ENC_CERT);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        BabaSSLServer.Builder serverBuilder = new BabaSSLServer.Builder();
        serverBuilder.setContextProtocol(ContextProtocol.TLCP11);
        serverBuilder.setCertTuple(certTuple);
        serverBuilder.setServerNames("www.example.com");
        serverBuilder.setClientAuth(clientAuth);
        serverBuilder.setMessage("Server");

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            JdkClient.Builder clientBuilder = createClientBuilder(
                    certTuple, clientCipherSuite);
            clientBuilder.setServerNames("www.example.com");
            try (JdkClient client = clientBuilder.build()) {
                client.connect("127.0.0.1", server.getPort());
            }
        } finally {
            executor.shutdown();
        }
    }

    @Test
    public void testResumption() throws Exception {
        testResumption(false, ClientAuth.NONE);
        testResumption(true, ClientAuth.NONE);
    }

    @Test
    public void testResumptionWithClientAuth() throws Exception {
        testResumption(false, ClientAuth.REQUIRED);
        testResumption(true, ClientAuth.REQUIRED);
    }

    private void testResumption(boolean useSessTicket, ClientAuth clientAuth)
            throws Exception {
        resumeSession(
                INTCA_CERT,
                SERVER_SIGN_CERT, SERVER_ENC_CERT,
                CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                useSessTicket,
                clientAuth);

        resumeSession(
                INTCA_CERT,
                SERVER_SIGN_CERT, SERVER_ENC_CERT,
                CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                useSessTicket,
                clientAuth);
    }

    private void resumeSession(
            FileCert trustedCert,
            FileCert signEeCert,
            FileCert encEeCert,
            CipherSuite clientCipherSuite,
            boolean useSessTicket,
            ClientAuth clientAuth) throws Exception {
        SmCertTuple certTuple = new SmCertTuple(trustedCert, signEeCert, encEeCert);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        BabaSSLServer.Builder serverBuilder = new BabaSSLServer.Builder();
        serverBuilder.setCertTuple(certTuple);
        serverBuilder.setCipherSuites(
                CipherSuite.TLCP_ECC_SM4_CBC_SM3,
                CipherSuite.TLCP_ECDHE_SM4_GCM_SM3,
                CipherSuite.TLCP_ECC_SM4_GCM_SM3,
                CipherSuite.TLCP_ECDHE_SM4_CBC_SM3);
        serverBuilder.setClientAuth(clientAuth);
        serverBuilder.setUseSessTicket(useSessTicket);

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            SSLContext context = null;
            long firstCreationTime = 0;
            try (JdkClient client = createClientBuilder(
                    certTuple, clientCipherSuite).build()) {
                client.connect("127.0.0.1", server.getPort());
                context = client.context;
                firstCreationTime = client.getSession().getCreationTime();
            }

            try (JdkClient client = createClientBuilder(
                    certTuple, clientCipherSuite,
                    context).build()) {
                client.connect("127.0.0.1", server.getPort());
                long secondCreationTime = client.getSession().getCreationTime();

                Assertions.assertEquals(firstCreationTime, secondCreationTime);
            }
        } finally {
            executor.shutdown();
        }
    }

    private JdkClient.Builder createClientBuilder(
            CertTuple certTuple, CipherSuite cipherSuite,
            SSLContext context) throws Exception {
        JdkClient.Builder clientBuilder = new JdkClient.Builder();
        clientBuilder.setCertTuple(certTuple);
        clientBuilder.setContextProtocol(ContextProtocol.TLCP11);
        clientBuilder.setProtocols(Protocol.TLCPV1_1);
        clientBuilder.setCipherSuites(cipherSuite);
        clientBuilder.setMessage(
                // An HTTP request asks to access the page.
                String.format("GET /%s HTTP/1.1\r\n", PAGE_FILE_NAME));
        clientBuilder.setReadResponse(true);
        clientBuilder.setContext(context);
        return clientBuilder;
    }

    private JdkClient.Builder createClientBuilder(
            CertTuple certTuple, CipherSuite cipherSuite)
            throws Exception {
        return createClientBuilder(certTuple, cipherSuite, null);
    }
}
