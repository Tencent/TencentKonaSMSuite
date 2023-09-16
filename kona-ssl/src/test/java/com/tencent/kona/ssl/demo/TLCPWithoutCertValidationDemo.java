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

package com.tencent.kona.ssl.demo;

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.pkix.PKIXInsts;
import com.tencent.kona.ssl.SSLInsts;
import com.tencent.kona.ssl.TestUtils;
import com.tencent.kona.sun.security.x509.SMCertificate;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.DefaultHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * A comprehensive demo for TLCP on custom trust manager.
 * The custom trust manager does NOT validate any certificate.
 */
public class TLCPWithoutCertValidationDemo {

    /** The CA certificate, which does NOT issue the below EE certificate.
     *
     *  Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             40:93:4b:f3:0d:7f:10:e4:fb:f8:d1:f5:61:a9:31:6d:b3:15:e4:8d
     *         Signature Algorithm: ecdsa-with-SHA256
     *         Issuer: CN = ec-ca
     *         Validity
     *             Not Before: Jun  8 06:28:27 2022 GMT
     *             Not After : Jun  5 06:28:27 2032 GMT
     *         Subject: CN = ec-ca
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (256 bit)
     *                 pub:
     *                     04:b3:ba:fa:d5:c1:62:4e:12:ec:3a:d1:a4:8b:a8:
     *                     7c:82:8f:49:11:2e:d0:f1:ca:be:37:cd:8f:68:0c:
     *                     db:b5:da:c7:c0:2a:c3:b9:f2:f8:d8:5b:40:a6:ca:
     *                     f1:05:67:d1:75:6b:56:db:6c:0a:ea:f3:9a:c4:ab:
     *                     85:db:4d:6b:30
     *                 ASN1 OID: prime256v1
     *                 NIST CURVE: P-256
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 1D:AD:7A:74:C4:22:DA:E9:BC:89:FC:92:DC:4D:D8:EF:B2:60:83:E8
     *             X509v3 Authority Key Identifier:
     *                 keyid:1D:AD:7A:74:C4:22:DA:E9:BC:89:FC:92:DC:4D:D8:EF:B2:60:83:E8
     *
     *             X509v3 Basic Constraints: critical
     *                 CA:TRUE
     *             X509v3 Key Usage: critical
     *                 Digital Signature, Certificate Sign, CRL Sign
     *     Signature Algorithm: ecdsa-with-SHA256
     *          30:46:02:21:00:c5:d3:e7:d7:4e:ea:9d:fc:54:75:ae:8a:5d:
     *          2b:53:d6:17:52:5d:1a:18:be:fb:d7:9c:b8:fd:be:4e:61:a8:
     *          b3:02:21:00:f3:94:59:95:d2:9d:8f:40:9d:b9:d0:48:eb:0d:
     *          c4:f9:13:7e:a9:1b:83:e2:4d:fd:7b:2f:fe:31:8d:6b:84:79
     */
    private static final String CA =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBhjCCASugAwIBAgIUQJNL8w1/EOT7+NH1YakxbbMV5I0wCgYIKoZIzj0EAwIw\n" +
            "EDEOMAwGA1UEAwwFZWMtY2EwHhcNMjIwNjA4MDYyODI3WhcNMzIwNjA1MDYyODI3\n" +
            "WjAQMQ4wDAYDVQQDDAVlYy1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLO6\n" +
            "+tXBYk4S7DrRpIuofIKPSREu0PHKvjfNj2gM27Xax8Aqw7ny+NhbQKbK8QVn0XVr\n" +
            "VttsCurzmsSrhdtNazCjYzBhMB0GA1UdDgQWBBQdrXp0xCLa6byJ/JLcTdjvsmCD\n" +
            "6DAfBgNVHSMEGDAWgBQdrXp0xCLa6byJ/JLcTdjvsmCD6DAPBgNVHRMBAf8EBTAD\n" +
            "AQH/MA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDAgNJADBGAiEAxdPn107qnfxU\n" +
            "da6KXStT1hdSXRoYvvvXnLj9vk5hqLMCIQDzlFmV0p2PQJ250EjrDcT5E36pG4Pi\n" +
            "Tf17L/4xjWuEeQ==\n" +
            "-----END CERTIFICATE-----";

    /** The sign certificate, which is NOT issued by the above CA.
     *
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             18:f6:d5:24:dd:35:22:b2:eb:f5:fb:25:48:87:4e:e2:ba:a9:73:03
     *         Signature Algorithm: SM2-with-SM3
     *         Issuer: CN = tlcp-intca
     *         Validity
     *             Not Before: May 11 11:56:38 2022 GMT
     *             Not After : May  8 11:56:38 2032 GMT
     *         Subject: CN = tlcp-server-sign
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (256 bit)
     *                 pub:
     *                     04:58:4f:5b:78:79:c4:b9:a4:b9:10:94:0f:6c:9b:
     *                     2c:5e:d6:d8:9c:b4:c7:65:ff:1e:00:6c:ef:27:23:
     *                     4e:c2:1e:35:ca:1c:f8:6d:3f:32:4b:bc:a1:47:da:
     *                     aa:90:4d:99:a7:e0:b9:df:2e:a6:8f:80:68:f1:f3:
     *                     29:aa:46:e3:83
     *                 ASN1 OID: SM2
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 21:EA:D6:26:3A:6B:1D:07:E1:0F:A1:13:80:15:F4:1B:C7:56:58:6B
     *             X509v3 Authority Key Identifier:
     *                 keyid:45:2F:DD:35:92:7E:77:44:9E:97:D4:D6:BC:63:58:19:69:F1:4D:BE
     *
     *             X509v3 Basic Constraints: critical
     *                 CA:FALSE
     *             X509v3 Key Usage: critical
     *                 Digital Signature
     *     Signature Algorithm: SM2-with-SM3
     *          30:45:02:20:5b:cf:1b:e3:fe:d1:82:3d:10:56:41:d1:e3:dc:
     *          c8:36:78:b0:c5:d8:e8:b4:14:64:4b:07:4a:36:45:6d:b7:b6:
     *          02:21:00:a4:8e:db:69:9c:cd:c7:53:4b:fb:35:81:68:74:47:
     *          27:76:35:e3:f5:10:c6:ba:36:0e:f4:dc:60:7a:05:e9:4a
     */
    private static final String SIGN_EE =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBkjCCATigAwIBAgIUGPbVJN01IrLr9fslSIdO4rqpcwMwCgYIKoEcz1UBg3Uw\n" +
            "FTETMBEGA1UEAwwKdGxjcC1pbnRjYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgx\n" +
            "MTU2MzhaMBsxGTAXBgNVBAMMEHRsY3Atc2VydmVyLXNpZ24wWTATBgcqhkjOPQIB\n" +
            "BggqgRzPVQGCLQNCAARYT1t4ecS5pLkQlA9smyxe1tictMdl/x4AbO8nI07CHjXK\n" +
            "HPhtPzJLvKFH2qqQTZmn4LnfLqaPgGjx8ymqRuODo2AwXjAdBgNVHQ4EFgQUIerW\n" +
            "JjprHQfhD6ETgBX0G8dWWGswHwYDVR0jBBgwFoAURS/dNZJ+d0Sel9TWvGNYGWnx\n" +
            "Tb4wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwCgYIKoEcz1UBg3UDSAAw\n" +
            "RQIgW88b4/7Rgj0QVkHR49zINniwxdjotBRkSwdKNkVtt7YCIQCkjttpnM3HU0v7\n" +
            "NYFodEcndjXj9RDGujYO9NxgegXpSg==\n" +
            "-----END CERTIFICATE-----";

    private static final String SIGN_EE_ID = "1234567812345678";

    // The sign certificate private key.
    private static final String SIGN_EE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg6wAH+egoZkKS3LKi\n" +
            "0okzJSYrn/yRVhNfmdhySuJic5ahRANCAARYT1t4ecS5pLkQlA9smyxe1tictMdl\n" +
            "/x4AbO8nI07CHjXKHPhtPzJLvKFH2qqQTZmn4LnfLqaPgGjx8ymqRuOD";

    /** The enc certificate, which is NOT issued by the above CA.
     *
     *  Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             18:f6:d5:24:dd:35:22:b2:eb:f5:fb:25:48:87:4e:e2:ba:a9:73:06
     *         Signature Algorithm: SM2-with-SM3
     *         Issuer: CN = tlcp-intca
     *         Validity
     *             Not Before: May 11 11:56:38 2022 GMT
     *             Not After : May  8 11:56:38 2032 GMT
     *         Subject: CN = tlcp-server-enc
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (256 bit)
     *                 pub:
     *                     04:04:1b:6a:d6:f5:de:02:4b:df:3b:75:07:c5:39:
     *                     2e:88:5e:44:9f:b8:5e:74:69:a8:84:39:3a:cc:74:
     *                     54:39:38:51:6d:b9:f1:a2:e5:53:de:9b:7f:7a:27:
     *                     be:71:d3:86:96:bd:1b:01:db:63:90:69:62:c3:0f:
     *                     d6:14:be:d6:40
     *                 ASN1 OID: SM2
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 34:28:D3:07:2A:D5:C6:79:C0:D7:88:4B:53:8C:27:E1:A4:38:79:08
     *             X509v3 Authority Key Identifier:
     *                 keyid:45:2F:DD:35:92:7E:77:44:9E:97:D4:D6:BC:63:58:19:69:F1:4D:BE
     *
     *             X509v3 Basic Constraints: critical
     *                 CA:FALSE
     *             X509v3 Key Usage: critical
     *                 Key Encipherment, Data Encipherment, Key Agreement
     *     Signature Algorithm: SM2-with-SM3
     *          30:44:02:20:03:d9:e0:be:17:b9:13:64:66:c7:da:51:c6:ed:
     *          94:ce:cf:1e:b6:39:8a:35:31:29:f7:d7:e8:4a:1d:f6:d9:f4:
     *          02:20:6b:35:88:40:c2:74:31:07:e7:fe:a5:f9:cf:41:33:f2:
     *          25:6a:c8:3c:59:c8:72:0e:16:36:eb:d4:36:44:40:49
     */
    private static final String ENC_EE =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBkDCCATegAwIBAgIUGPbVJN01IrLr9fslSIdO4rqpcwYwCgYIKoEcz1UBg3Uw\n" +
            "FTETMBEGA1UEAwwKdGxjcC1pbnRjYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgx\n" +
            "MTU2MzhaMBoxGDAWBgNVBAMMD3RsY3Atc2VydmVyLWVuYzBZMBMGByqGSM49AgEG\n" +
            "CCqBHM9VAYItA0IABAQbatb13gJL3zt1B8U5LoheRJ+4XnRpqIQ5Osx0VDk4UW25\n" +
            "8aLlU96bf3onvnHThpa9GwHbY5BpYsMP1hS+1kCjYDBeMB0GA1UdDgQWBBQ0KNMH\n" +
            "KtXGecDXiEtTjCfhpDh5CDAfBgNVHSMEGDAWgBRFL901kn53RJ6X1Na8Y1gZafFN\n" +
            "vjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIDODAKBggqgRzPVQGDdQNHADBE\n" +
            "AiAD2eC+F7kTZGbH2lHG7ZTOzx62OYo1MSn31+hKHfbZ9AIgazWIQMJ0MQfn/qX5\n" +
            "z0Ez8iVqyDxZyHIOFjbr1DZEQEk=\n" +
            "-----END CERTIFICATE-----";

    private static final String ENC_EE_ID = "1234567812345678";

    // The enc certificate private key.
    private static final String ENC_EE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgqFilR+zUyRQWREb+\n" +
            "rb5uIldK/bPE1l20DzNpuMt55VehRANCAAQEG2rW9d4CS987dQfFOS6IXkSfuF50\n" +
            "aaiEOTrMdFQ5OFFtufGi5VPem396J75x04aWvRsB22OQaWLDD9YUvtZA";

    private static final String PASSWORD = "password";
    private static final String TRUSTSTORE = "truststore";
    private static final String KEYSTORE = "keystore";

    @BeforeAll
    public static void setup() throws Exception {
        // Output debug info.
//        System.setProperty("com.tencent.kona.ssl.debug", "all");

        // Add providers.
        TestUtils.addProviders();

        deleteStoreFiles();
        createStoreFiles();
    }

    private static void createStoreFiles() throws Exception {
        // Create trust store file
        createTrustStoreFile(CA, null);

        // Create key store file
        createKeyStoreFile(
                SIGN_EE, SIGN_EE_ID, SIGN_EE_KEY,
                ENC_EE, ENC_EE_ID, ENC_EE_KEY);
    }

    private static void createTrustStoreFile(String caStr, String caId)
            throws Exception {
        KeyStore trustStore = PKIXInsts.getKeyStore("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("tlcp-trust-demo", loadCert(caStr, caId));
        try (FileOutputStream out = new FileOutputStream(
                Paths.get(TRUSTSTORE).toFile())) {
            trustStore.store(out, PASSWORD.toCharArray());
        }
    }

    private static void createKeyStoreFile(
            String signEeStr, String signEeId, String signEeKeyStr,
            String encEeStr, String encEeId, String encEeKeyStr)
            throws Exception {
        KeyStore keyStore = PKIXInsts.getKeyStore("PKCS12");
        keyStore.load(null, null);

        keyStore.setKeyEntry("tlcp-sign-ee-demo",
                loadPrivateKey(signEeKeyStr),
                PASSWORD.toCharArray(),
                new Certificate[] { loadCert(signEeStr, signEeId) } );
        keyStore.setKeyEntry("tlcp-enc-ee-demo",
                loadPrivateKey(encEeKeyStr),
                PASSWORD.toCharArray(),
                new Certificate[] { loadCert(encEeStr, encEeId) } );

        try (FileOutputStream out = new FileOutputStream(
                Paths.get(KEYSTORE).toFile())) {
            keyStore.store(out, PASSWORD.toCharArray());
        }
    }

    private static X509Certificate loadCert(String certPEM, String id)
            throws Exception {
        CertificateFactory certFactory = PKIXInsts.getCertificateFactory(
                "X.509");
        X509Certificate x509Cert = (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(certPEM.getBytes()));

        if (id != null && !id.isEmpty()) {
            ((SMCertificate) x509Cert).setId(id.getBytes(
                    StandardCharsets.UTF_8));
        }

        return x509Cert;
    }

    private static PrivateKey loadPrivateKey(String keyPEM) throws Exception {
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                Base64.getMimeDecoder().decode(keyPEM));
        KeyFactory keyFactory = CryptoInsts.getKeyFactory("EC");
        return keyFactory.generatePrivate(privateKeySpec);
    }

    @AfterAll
    public static void clean() throws IOException {
        deleteStoreFiles();
    }

    private static void deleteStoreFiles() throws IOException {
        Files.deleteIfExists(Paths.get(TRUSTSTORE));
        Files.deleteIfExists(Paths.get(KEYSTORE));
    }

    @Test
    public void tlcpDemo() throws Exception {
        Server server = createServer();
        server.start();
        int port = server.getURI().getPort();

        CloseableHttpClient client = createClient();

        // Access Servlet /hello over HTTPS scheme.
        HttpGet getMethod = new HttpGet(
                String.format("https://localhost:%d/hello", port));
        CloseableHttpResponse response = client.execute(getMethod);
        client.close();

        System.out.println(response.toString());
        response.close();

        server.stop();
    }

    // Create Jetty server, which can publish service over TLCP.
    private static Server createServer() throws Exception {
        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        sslContextFactory.setSslContext(createContext());

        HttpConfiguration config = new HttpConfiguration();
        config.setSecureScheme("https");
        config.addCustomizer(new SecureRequestCustomizer());

        Server server = new Server();
        ServerConnector httpsConnector = new ServerConnector(server,
                new SslConnectionFactory(sslContextFactory,
                        HttpVersion.HTTP_1_1.asString()),
                new HttpConnectionFactory(config));
        httpsConnector.setPort(0);
        server.addConnector(httpsConnector);

        ServletContextHandler context = new ServletContextHandler();
        context.setContextPath("/");
        context.addServlet(HelloServlet.class, "/hello");
        server.setHandler(new HandlerList(context, new DefaultHandler()));

        return server;
    }

    // Create Apache HttpClient client, which supports TLCP connection.
    private static CloseableHttpClient createClient() throws Exception {
        SSLContext context = createContext();

        SSLConnectionSocketFactory socketFactory
                = new SSLConnectionSocketFactory(
                        context, NoopHostnameVerifier.INSTANCE);
        CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(socketFactory).build();
        return httpClient;
    }

    private static SSLContext createContext() throws Exception {
        // Load trust store
        KeyStore trustStore = PKIXInsts.getKeyStore("PKCS12");
        try (FileInputStream keyStoreIn = new FileInputStream(TRUSTSTORE)) {
            trustStore.load(keyStoreIn, PASSWORD.toCharArray());
        }

        TrustManagerFactory tmf = SSLInsts.getTrustManagerFactory("PKIX");
        tmf.init(trustStore);

        // Create the custom trust managers with the existing trust managers.
        TrustManager[] trustManagers = tmf.getTrustManagers();
        for (int i = 0; i < trustManagers.length; i++) {
            TrustManager trustManager = trustManagers[i];
            if (trustManager instanceof X509TrustManager) {
                trustManagers[i] = new CustomTrustManager(
                        (X509TrustManager) trustManager);
            }
        }

        // Load key store
        KeyStore keyStore = PKIXInsts.getKeyStore("PKCS12");
        try (FileInputStream keyStoreIn = new FileInputStream(KEYSTORE)) {
            keyStore.load(keyStoreIn, PASSWORD.toCharArray());
        }
        KeyManagerFactory kmf = SSLInsts.getKeyManagerFactory("NewSunX509");
        kmf.init(keyStore, PASSWORD.toCharArray());

        SSLContext context = SSLInsts.getSSLContext("TLCPv1.1");
        context.init(kmf.getKeyManagers(), trustManagers, new SecureRandom());
        return context;
    }

    // A custom trust manager that does NOT validate any certificate.
    private static class CustomTrustManager implements X509TrustManager {

        private final X509TrustManager trustManager;

        CustomTrustManager(X509TrustManager trustManager) {
            this.trustManager = trustManager;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            // Do nothing
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            // Do nothing
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return trustManager.getAcceptedIssuers();
        }
    }

    public static class HelloServlet extends HttpServlet {

        private static final long serialVersionUID = -4748362333014218314L;

        @Override
        public void doGet(
                HttpServletRequest request, HttpServletResponse response)
                throws ServletException, IOException {
            response.setContentType("text/plain");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().println("Hello!");
        }

        @Override
        public void doPost(
                HttpServletRequest request, HttpServletResponse response)
                throws ServletException, IOException {
            doGet(request, response);
        }
    }
}
