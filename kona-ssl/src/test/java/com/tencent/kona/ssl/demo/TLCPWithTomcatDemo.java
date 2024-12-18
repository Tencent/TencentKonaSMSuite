/*
 * Copyright (C) 2023, 2024, THL A29 Limited, a Tencent company. All rights reserved.
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
import com.tencent.kona.ssl.TestUtils;
import com.tencent.kona.sun.security.x509.SMCertificate;
import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.CoyoteAdapter;
import org.apache.catalina.startup.Tomcat;
import org.apache.coyote.http11.AbstractHttp11JsseProtocol;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLUtil;
import org.apache.tomcat.util.net.SSLUtilBase;
import org.apache.tomcat.util.net.jsse.JSSEImplementation;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * A comprehensive demo for TLCP with Tomcat.
 *
 * This demo may not be the best practice.
 * Please figure out the best way for your real projects by your self.
 */
public class TLCPWithTomcatDemo {

    /* The CA certificate.
     *
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             21:9c:f4:c5:db:bb:03:3e:69:d2:32:6a:46:77:aa:f7:a3:6b:68:52
     *         Signature Algorithm: sm3WithSM2Sign
     *         Issuer: CN = tlcp-ca
     *         Validity
     *             Not Before: Mar 10 11:08:29 2022 GMT
     *             Not After : Mar  7 11:08:29 2032 GMT
     *         Subject: CN = tlcp-intca
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (256 bit)
     *                 pub:
     *                     04:bf:d8:1f:2c:1f:47:4f:0d:e6:04:ab:14:73:4f:
     *                     75:88:44:5d:ec:59:25:3d:9b:8c:74:33:1d:f4:66:
     *                     c6:97:1a:db:41:21:4a:ab:34:75:7d:e8:01:03:78:
     *                     8f:d8:e7:c9:cd:8f:fd:fe:45:82:d8:02:d0:53:2a:
     *                     cb:d0:e4:c8:61
     *                 ASN1 OID: SM2
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 CB:67:1D:38:EC:4A:66:5D:98:76:4D:71:5F:47:7D:43:3E:59:07:FD
     *             X509v3 Authority Key Identifier:
     *                 keyid:5A:6A:53:54:DC:B7:80:2A:6B:56:C2:37:F8:18:F2:81:A0:81:B3:4D
     *
     *             X509v3 Basic Constraints: critical
     *                 CA:TRUE
     *             X509v3 Key Usage: critical
     *                 Digital Signature, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign
     *             X509v3 Extended Key Usage: critical
     *                 OCSP Signing, Time Stamping
     *     Signature Algorithm: sm3WithSM2Sign
     *          30:45:02:21:00:98:ea:df:4b:50:eb:8d:f8:19:9e:32:15:11:
     *          68:01:26:8d:f0:a8:ed:5e:28:a1:f4:14:d9:ed:31:2c:7f:61:
     *          36:02:20:77:64:87:fe:aa:50:01:e2:1c:ec:e0:d7:d1:8e:1a:
     *          e5:5f:5e:f6:48:0a:60:3c:7c:68:1d:4c:5e:81:fd:d2:5e
     */
    private static final String CA =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBsDCCAVagAwIBAgIUIZz0xdu7Az5p0jJqRneq96NraFIwCgYIKoEcz1UBg3Uw\n" +
            "EjEQMA4GA1UEAwwHdGxjcC1jYTAeFw0yMjAzMTAxMTA4MjlaFw0zMjAzMDcxMTA4\n" +
            "MjlaMBUxEzARBgNVBAMMCnRsY3AtaW50Y2EwWTATBgcqhkjOPQIBBggqgRzPVQGC\n" +
            "LQNCAAS/2B8sH0dPDeYEqxRzT3WIRF3sWSU9m4x0Mx30ZsaXGttBIUqrNHV96AED\n" +
            "eI/Y58nNj/3+RYLYAtBTKsvQ5Mhho4GGMIGDMB0GA1UdDgQWBBTLZx047EpmXZh2\n" +
            "TXFfR31DPlkH/TAfBgNVHSMEGDAWgBRaalNU3LeAKmtWwjf4GPKBoIGzTTAPBgNV\n" +
            "HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBvjAgBgNVHSUBAf8EFjAUBggrBgEF\n" +
            "BQcDCQYIKwYBBQUHAwgwCgYIKoEcz1UBg3UDSAAwRQIhAJjq30tQ6434GZ4yFRFo\n" +
            "ASaN8KjtXiih9BTZ7TEsf2E2AiB3ZIf+qlAB4hzs4NfRjhrlX172SApgPHxoHUxe\n" +
            "gf3SXg==\n" +
            "-----END CERTIFICATE-----";

    // The CA private key.
    private static final String CA_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgPWgd9v0oxNwV1/nL\n" +
            "UVaZuqCxxJmSeyVzvaWgb4lxB3qhRANCAAS/2B8sH0dPDeYEqxRzT3WIRF3sWSU9\n" +
            "m4x0Mx30ZsaXGttBIUqrNHV96AEDeI/Y58nNj/3+RYLYAtBTKsvQ5Mhh";

    /* The sign certificate.
     *
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             4d:98:a4:22:6f:c7:f9:74:8d:56:c6:1c:7e:7e:12:b6:52:81:79
     *         Signature Algorithm: SM2-with-SM3
     *         Issuer: CN = tlcp-intca
     *         Validity
     *             Not Before: Apr  3 23:58:03 2022 GMT
     *             Not After : Mar 31 23:58:03 2032 GMT
     *         Subject: CN = localhost
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (256 bit)
     *                 pub:
     *                     04:63:d7:44:3b:17:45:96:f4:d7:ff:a2:2c:1d:34:
     *                     bf:81:6e:aa:2f:25:af:f0:5d:e0:75:1c:40:31:dd:
     *                     8c:8d:29:8d:c0:fe:20:3e:2a:f8:97:36:31:d0:bb:
     *                     65:6b:87:ad:6a:a6:26:20:05:05:aa:a4:c3:00:c6:
     *                     79:62:18:9b:a5
     *                 ASN1 OID: SM2
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 DA:85:F0:6C:9D:E9:17:89:A6:48:3D:18:F5:8B:D1:50:BF:6A:13:59
     *             X509v3 Authority Key Identifier:
     *                 keyid:CB:67:1D:38:EC:4A:66:5D:98:76:4D:71:5F:47:7D:43:3E:59:07:FD
     *
     *             X509v3 Basic Constraints: critical
     *                 CA:FALSE
     *             X509v3 Key Usage: critical
     *                 Digital Signature, Certificate Sign, CRL Sign
     *     Signature Algorithm: SM2-with-SM3
     *          30:44:02:20:55:dc:e4:91:84:68:72:e9:40:4c:cc:e0:a4:8b:
     *          ce:17:05:47:64:1b:e4:bb:15:b4:e2:8f:f3:b9:a9:b5:81:cd:
     *          02:20:75:b2:50:7f:d1:49:79:a5:24:a1:bc:d7:e4:19:56:9e:
     *          e2:40:a9:29:c1:c9:83:38:10:79:fb:2c:fa:2a:be:50
     */
    private static final String SIGN_EE =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBiTCCATCgAwIBAgITTZikIm/H+XSNVsYcfn4StlKBeTAKBggqgRzPVQGDdTAV\n" +
            "MRMwEQYDVQQDDAp0bGNwLWludGNhMB4XDTIyMDQwMzIzNTgwM1oXDTMyMDMzMTIz\n" +
            "NTgwM1owFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoEcz1UB\n" +
            "gi0DQgAEY9dEOxdFlvTX/6IsHTS/gW6qLyWv8F3gdRxAMd2MjSmNwP4gPir4lzYx\n" +
            "0Ltla4etaqYmIAUFqqTDAMZ5YhibpaNgMF4wHQYDVR0OBBYEFNqF8Gyd6ReJpkg9\n" +
            "GPWL0VC/ahNZMB8GA1UdIwQYMBaAFMtnHTjsSmZdmHZNcV9HfUM+WQf9MAwGA1Ud\n" +
            "EwEB/wQCMAAwDgYDVR0PAQH/BAQDAgGGMAoGCCqBHM9VAYN1A0cAMEQCIFXc5JGE\n" +
            "aHLpQEzM4KSLzhcFR2Qb5LsVtOKP87mptYHNAiB1slB/0Ul5pSShvNfkGVae4kCp\n" +
            "KcHJgzgQefss+iq+UA==\n" +
            "-----END CERTIFICATE-----";

    private static final String SIGN_EE_ID = "1234567812345678";

    // The sign certificate private key.
    private static final String SIGN_EE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg5ITc2VNmxpeum3gN\n" +
            "f2LUjGmdc3G45uGNDFeiRLYxdKmhRANCAARj10Q7F0WW9Nf/oiwdNL+BbqovJa/w\n" +
            "XeB1HEAx3YyNKY3A/iA+KviXNjHQu2Vrh61qpiYgBQWqpMMAxnliGJul";

    /* The enc certificate.
     *
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             4d:98:a4:22:6f:c7:f9:74:8d:56:c6:1c:7e:7e:12:b6:52:81:78
     *         Signature Algorithm: SM2-with-SM3
     *         Issuer: CN = tlcp-intca
     *         Validity
     *             Not Before: Apr  3 23:57:39 2022 GMT
     *             Not After : Mar 31 23:57:39 2032 GMT
     *         Subject: CN = localhost
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (256 bit)
     *                 pub:
     *                     04:ab:85:de:73:98:9e:44:01:23:2c:8c:f8:53:29:
     *                     ae:f5:1e:66:f1:6d:25:1f:22:69:7d:b4:9b:89:86:
     *                     1e:9a:65:09:7d:2c:df:fb:b8:41:ea:ff:c1:73:d0:
     *                     f6:60:e0:f7:bd:73:2e:a6:be:c6:b5:c5:d5:13:01:
     *                     1f:fe:2a:28:a6
     *                 ASN1 OID: SM2
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 64:35:36:FB:4E:6E:16:44:7E:21:A9:FE:2E:FF:BC:91:9B:ED:15:6D
     *             X509v3 Authority Key Identifier:
     *                 keyid:CB:67:1D:38:EC:4A:66:5D:98:76:4D:71:5F:47:7D:43:3E:59:07:FD
     *
     *             X509v3 Basic Constraints: critical
     *                 CA:FALSE
     *             X509v3 Key Usage: critical
     *                 Key Encipherment, Data Encipherment, Key Agreement
     *     Signature Algorithm: SM2-with-SM3
     *          30:46:02:21:00:b2:1b:8d:78:a2:19:bd:39:63:5b:6c:24:69:
     *          50:e2:85:b6:2b:a2:b8:15:b9:29:64:60:b2:07:f1:77:f1:70:
     *          7e:02:21:00:be:d2:f1:d7:a8:a1:cd:f3:5e:25:06:c1:9f:5e:
     *          ec:67:9b:4d:06:9b:39:84:34:07:c9:d1:b7:81:14:33:21:21
     */
    private static final String ENC_EE =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBizCCATCgAwIBAgITTZikIm/H+XSNVsYcfn4StlKBeDAKBggqgRzPVQGDdTAV\n" +
            "MRMwEQYDVQQDDAp0bGNwLWludGNhMB4XDTIyMDQwMzIzNTczOVoXDTMyMDMzMTIz\n" +
            "NTczOVowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoEcz1UB\n" +
            "gi0DQgAEq4Xec5ieRAEjLIz4Uymu9R5m8W0lHyJpfbSbiYYemmUJfSzf+7hB6v/B\n" +
            "c9D2YOD3vXMupr7GtcXVEwEf/ioopqNgMF4wHQYDVR0OBBYEFGQ1NvtObhZEfiGp\n" +
            "/i7/vJGb7RVtMB8GA1UdIwQYMBaAFMtnHTjsSmZdmHZNcV9HfUM+WQf9MAwGA1Ud\n" +
            "EwEB/wQCMAAwDgYDVR0PAQH/BAQDAgM4MAoGCCqBHM9VAYN1A0kAMEYCIQCyG414\n" +
            "ohm9OWNbbCRpUOKFtiuiuBW5KWRgsgfxd/FwfgIhAL7S8deooc3zXiUGwZ9e7Geb\n" +
            "TQabOYQ0B8nRt4EUMyEh\n" +
            "-----END CERTIFICATE-----";

    private static final String ENC_EE_ID = "1234567812345678";

    // The enc certificate private key.
    private static final String ENC_EE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg+4a+CrNbNAyJ75Rm\n" +
            "fN97JHcsbL9lqM5CWBFv0ooD4b2hRANCAASrhd5zmJ5EASMsjPhTKa71HmbxbSUf\n" +
            "Iml9tJuJhh6aZQl9LN/7uEHq/8Fz0PZg4Pe9cy6mvsa1xdUTAR/+Kiim";

    private static final String PASSWORD = "password";

    @Test
    public void tlcpDemo() throws Exception {
         // Output debug info.
//        System.setProperty("com.tencent.kona.ssl.debug", "all");

        // Just use SM2 curve for key share
        System.setProperty("com.tencent.kona.ssl.namedGroups", "curveSM2");

        // Add providers.
        TestUtils.addProviders();

        KonaConnector httpsConnector = new KonaConnector("HTTP/1.1");
        httpsConnector.setPort(0);
        httpsConnector.setProperty("SSLEnabled", "true");

        SSLHostConfig sslConfig = new KonaSSLHostConfig();
        SSLHostConfigCertificate certConfig = new SSLHostConfigCertificate(
                sslConfig, SSLHostConfigCertificate.Type.EC);
        certConfig.setCertificateKeystore(createKeyStore(
                SIGN_EE, SIGN_EE_ID, SIGN_EE_KEY,
                ENC_EE, ENC_EE_ID, ENC_EE_KEY));
        certConfig.setCertificateKeystorePassword(PASSWORD);
        sslConfig.addCertificate(certConfig);
        sslConfig.setTrustStore(createTrustStore(CA, null));
        httpsConnector.addSslHostConfig(sslConfig);

        Tomcat tomcat = new Tomcat();
        tomcat.setBaseDir("build/tomcat");
        tomcat.getService().addConnector(httpsConnector);

        Context rootCtx = tomcat.addContext(
                "", Paths.get(".").toFile().getAbsolutePath());
        Tomcat.addServlet(rootCtx, "Hello", new HelloServlet());
        rootCtx.addServletMappingDecoded("/hello", "Hello");

        tomcat.start();

        // Wait for the server
        TimeUnit.MILLISECONDS.sleep(500);

        HttpClient client = createClient();
        client.start();

        // Access Servlet /hello over HTTPS scheme.
        ContentResponse response = client.GET(
                new URI(String.format("https://localhost:%d/hello",
                        tomcat.getConnector().getLocalPort())));
        client.stop();
        System.out.println(response.getContentAsString());

        tomcat.stop();
    }

    // Create Jetty client, which supports TLS connection.
    private static HttpClient createClient() throws Exception {
        SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
        sslContextFactory.setSslContext(createContext());

        HttpClient httpClient = new HttpClient(sslContextFactory);
        return httpClient;
    }

    private static SSLContext createContext() throws Exception {
        KeyStore trustStore = createTrustStore(CA, null);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", "KonaSSL");
        tmf.init(trustStore);

        KeyStore keyStore = createKeyStore(
                SIGN_EE, SIGN_EE_ID, SIGN_EE_KEY,
                ENC_EE, ENC_EE_ID, ENC_EE_KEY);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509", "KonaSSL");
        kmf.init(keyStore, PASSWORD.toCharArray());

        SSLContext context = SSLContext.getInstance("TLCPv1.1", "KonaSSL");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        return context;
    }

    private static KeyStore createTrustStore(String caStr, String caId)
            throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12", "KonaPKIX");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("tlcp-trust-demo", loadCert(caStr, caId));
        return trustStore;
    }

    private static KeyStore createKeyStore(
            String signEeStr, String signEeId, String signEeKeyStr,
            String encEeStr, String encEeId, String encEeKeyStr)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "KonaPKIX");
        keyStore.load(null, null);

        keyStore.setKeyEntry("tlcp-sign-ee-demo",
                loadPrivateKey(signEeKeyStr),
                PASSWORD.toCharArray(),
                new Certificate[] { loadCert(signEeStr, signEeId) } );
        keyStore.setKeyEntry("tlcp-enc-ee-demo",
                loadPrivateKey(encEeKeyStr),
                PASSWORD.toCharArray(),
                new Certificate[] { loadCert(encEeStr, encEeId) } );

        return keyStore;
    }

    private static X509Certificate loadCert(String certPEM, String id)
            throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance(
                "X.509", "KonaPKIX");
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
        KeyFactory keyFactory = KeyFactory.getInstance("EC", CryptoInsts.PROV);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    public static class KonaConnector extends Connector {

        public KonaConnector(String protocol) {
            super(protocol);
        }

        @Override
        protected void initInternal() throws LifecycleException {
            // Initialize adapter
            adapter = new CoyoteAdapter(this);
            protocolHandler.setAdapter(adapter);

            // Make sure parseBodyMethodsSet has a default
            if (parseBodyMethodsSet == null) {
                setParseBodyMethods(getParseBodyMethods());
            }

            // Use custom JSSEImplementation
            ((AbstractHttp11JsseProtocol<?>) protocolHandler).setSslImplementationName(
                    KonaSSLImpl.class.getName());

            try {
                protocolHandler.init();
            } catch (Exception e) {
                throw new LifecycleException(sm.getString(
                        "coyoteConnector.protocolHandlerInitializationFailed"), e);
            }
        }
    }

    public static class KonaSSLHostConfig extends SSLHostConfig {

        private static final long serialVersionUID = 3931709572625017292L;

        @Override
        public Set<String> getProtocols() {
            return Collections.singleton("TLCPv1.1");
        }

        @Override
        public List<String> getJsseCipherNames() {
            return Collections.singletonList("TLCP_ECC_SM4_GCM_SM3");
        }
    }

    public static class KonaSSLImpl extends JSSEImplementation {

        @Override
        public SSLUtil getSSLUtil(SSLHostConfigCertificate certificate) {
            return new KonaSSLUtil(certificate);
        }
    }

    public static class KonaSSLUtil extends SSLUtilBase {

        private static final Log LOG = LogFactory.getLog(KonaSSLUtil.class);

        protected KonaSSLUtil(SSLHostConfigCertificate certificate) {
            super(certificate);
        }

        protected KonaSSLUtil(SSLHostConfigCertificate certificate,
                              boolean warnTls13) {
            super(certificate, warnTls13);
        }

        @Override
        public KeyManager[] getKeyManagers() throws Exception {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509", "KonaSSL");
            kmf.init(certificate.getCertificateKeystore(),
                    certificate.getCertificateKeystorePassword().toCharArray());
            return kmf.getKeyManagers();
        }

        @Override
        protected Log getLog() {
            return LOG;
        }

        @Override
        protected Set<String> getImplementedProtocols() {
            return Collections.singleton("TLCPv1.1");
        }

        @Override
        protected Set<String> getImplementedCiphers() {
            return Collections.singleton("TLCP_ECC_SM4_GCM_SM3");
        }

        @Override
        protected boolean isTls13RenegAuthAvailable() {
            // TLS 1.3 does not support authentication after the initial handshake
            return false;
        }

        @Override
        public org.apache.tomcat.util.net.SSLContext createSSLContextInternal(
                List<String> negotiableProtocols)
                throws NoSuchAlgorithmException, NoSuchProviderException {
            return new KonaSSLContext(sslHostConfig.getSslProtocol());
        }
    }

    public static class KonaSSLContext
            implements org.apache.tomcat.util.net.SSLContext {

        private final SSLContext context;
        private KeyManager[] kms;
        private TrustManager[] tms;

        public KonaSSLContext(String protocol)
                throws NoSuchAlgorithmException, NoSuchProviderException {
            context = SSLContext.getInstance(protocol, "KonaSSL");
        }

        @Override
        public void init(KeyManager[] kms, TrustManager[] tms, SecureRandom random)
                throws KeyManagementException {
            this.kms = kms;
            this.tms = tms;
            context.init(kms, tms, random);
        }

        @Override
        public void destroy() {
        }

        @Override
        public SSLSessionContext getServerSessionContext() {
            return context.getServerSessionContext();
        }

        @Override
        public SSLEngine createSSLEngine() {
            return context.createSSLEngine();
        }

        @Override
        public SSLServerSocketFactory getServerSocketFactory() {
            return context.getServerSocketFactory();
        }

        @Override
        public SSLParameters getSupportedSSLParameters() {
            return context.getSupportedSSLParameters();
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            X509Certificate[] result = null;
            if (kms != null) {
                for (int i = 0; i < kms.length && result == null; i++) {
                    if (kms[i] instanceof X509KeyManager) {
                        result = ((X509KeyManager) kms[i]).getCertificateChain(alias);
                    }
                }
            }
            return result;
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            Set<X509Certificate> certs = new HashSet<>();
            if (tms != null) {
                for (TrustManager tm : tms) {
                    if (tm instanceof X509TrustManager) {
                        X509Certificate[] accepted = ((X509TrustManager) tm).getAcceptedIssuers();
                        if (accepted != null) {
                            certs.addAll(Arrays.asList(accepted));
                        }
                    }
                }
            }
            return certs.toArray(new X509Certificate[0]);
        }
    }

    public static class HelloServlet extends HttpServlet {

        private static final long serialVersionUID = -3697586958032851435L;

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
