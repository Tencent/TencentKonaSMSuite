/*
 * Copyright (C) 2023, THL A29 Limited, a Tencent company. All rights reserved.
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

import com.tencent.kona.ssl.TestUtils;
import com.tencent.kona.sun.security.x509.SMCertificate;
import io.grpc.Channel;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.CipherSuiteFilter;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.JdkSslContext;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.StreamSupport;

/**
 * A comprehensive demo for TLS 1.3 connection with RFC 8998-defined
 * cipher suite, named group and signature scheme.
 */
public class TLSWithGRPCDemo {

    /* The CA certificate.
     *
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             66:b3:f0:17:73:ea:58:60:dc:ae:15:5b:7b:ca:d7:e0:3c:09:98:45
     *         Signature Algorithm: sm3WithSM2Sign
     *         Issuer: CN = ca-sm2sm2
     *         Validity
     *             Not Before: Sep 11 20:15:16 2021 GMT
     *             Not After : Sep  9 20:15:16 2031 GMT
     *         Subject: CN = intca-sm2sm2-sm2sm2
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (256 bit)
     *                 pub:
     *                     04:62:d7:db:de:87:3d:46:51:c4:25:00:d3:0b:68:
     *                     ed:f9:64:ff:e4:62:9b:80:85:fb:6a:f8:c3:3f:4b:
     *                     38:e5:72:5c:92:b8:d8:33:0f:9f:50:da:53:93:52:
     *                     06:d2:e6:90:f2:ae:55:c8:c1:40:4f:50:17:a4:b8:
     *                     e2:7b:ba:8f:64
     *                 ASN1 OID: SM2
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 BD:AA:64:6D:4D:40:33:81:B7:50:B3:4D:2F:12:7D:8E:A6:EF:64:42
     *             X509v3 Authority Key Identifier:
     *                 keyid:0A:61:C1:22:D6:20:06:80:48:68:8A:96:EF:08:47:75:FF:32:01:84
     *
     *             X509v3 Basic Constraints: critical
     *                 CA:TRUE
     *             X509v3 Key Usage: critical
     *                 Digital Signature, Certificate Sign, CRL Sign
     *             X509v3 Extended Key Usage: critical
     *                 OCSP Signing
     *     Signature Algorithm: sm3WithSM2Sign
     *          30:45:02:20:61:67:6c:27:97:6b:b2:29:bb:d4:d9:d2:4b:df:
     *          51:75:e9:a4:8c:4d:6a:47:dd:5a:80:87:0e:e2:3e:65:ca:3c:
     *          02:21:00:eb:87:26:69:1c:14:0b:ff:43:32:16:1d:bd:21:b3:
     *          b5:8d:fe:dd:ec:ad:d7:60:ff:c2:43:77:87:9e:63:b4:16
     */
    private static final String CA =
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
            "-----END CERTIFICATE-----";

    // The CA private key.
    private static final String CA_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKWfrthUXfdgXGGI9\n" +
            "qBJO/uIvABG6E4gcq/vMeGldll+hRANCAARi19vehz1GUcQlANMLaO35ZP/kYpuA\n" +
            "hftq+MM/SzjlclySuNgzD59Q2lOTUgbS5pDyrlXIwUBPUBekuOJ7uo9k";

    /* The end entity certificate with ID "custom-id".
     *
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             47:d5:15:57:b6:d3:34:d8:dc:c8:8e:1f:e6:37:0e:62:1f:b1:98:a7
     *         Signature Algorithm: SM2-with-SM3
     *         Issuer: CN = intca-sm2sm2-sm2sm2
     *         Validity
     *             Not Before: Jan 20 04:36:34 2022 GMT
     *             Not After : Jan 18 04:36:34 2032 GMT
     *         Subject: CN = localhost
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (256 bit)
     *                 pub:
     *                     04:99:43:82:0c:7a:2e:39:32:45:61:0f:24:85:8e:
     *                     90:f5:d7:b3:33:e5:f2:6c:1f:cb:81:b6:5b:47:67:
     *                     32:4f:a3:0d:e8:b0:d2:0e:1c:b7:4d:57:8d:e0:45:
     *                     c8:28:e6:07:be:b8:9b:12:a0:bb:f2:d3:48:fd:fd:
     *                     73:8a:b0:05:4e
     *                 ASN1 OID: SM2
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 E5:C6:9A:5B:66:F4:49:EF:2D:A9:74:FF:BB:5B:15:A9:EE:7E:2E:6F
     *             X509v3 Authority Key Identifier:
     *                 keyid:BD:AA:64:6D:4D:40:33:81:B7:50:B3:4D:2F:12:7D:8E:A6:EF:64:42
     *
     *     Signature Algorithm: SM2-with-SM3
     *          30:45:02:21:00:e9:87:48:f5:05:67:7b:1f:4e:33:62:73:b7:
     *          9c:06:2b:97:65:bf:29:66:dc:69:04:e9:53:fa:e2:60:db:63:
     *          bb:02:20:43:3c:cd:5f:2b:e3:2a:e6:74:e9:a4:2d:d0:15:bf:
     *          a2:36:1d:fd:a6:b4:df:f3:c1:88:71:2d:99:7e:c9:8d:1b
     */
    private static final String EE =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBdjCCARygAwIBAgIUR9UVV7bTNNjcyI4f5jcOYh+xmKcwCgYIKoEcz1UBg3Uw\n" +
            "HjEcMBoGA1UEAwwTaW50Y2Etc20yc20yLXNtMnNtMjAeFw0yMjAxMjAwNDM2MzRa\n" +
            "Fw0zMjAxMTgwNDM2MzRaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49\n" +
            "AgEGCCqBHM9VAYItA0IABJlDggx6LjkyRWEPJIWOkPXXszPl8mwfy4G2W0dnMk+j\n" +
            "Deiw0g4ct01XjeBFyCjmB764mxKgu/LTSP39c4qwBU6jQjBAMB0GA1UdDgQWBBTl\n" +
            "xppbZvRJ7y2pdP+7WxWp7n4ubzAfBgNVHSMEGDAWgBS9qmRtTUAzgbdQs00vEn2O\n" +
            "pu9kQjAKBggqgRzPVQGDdQNIADBFAiEA6YdI9QVnex9OM2Jzt5wGK5dlvylm3GkE\n" +
            "6VP64mDbY7sCIEM8zV8r4yrmdOmkLdAVv6I2Hf2mtN/zwYhxLZl+yY0b\n" +
            "-----END CERTIFICATE-----";

    private static final String EE_ID = "custom-id";

    // The end entity private key.
    private static final String EE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgyfT1QME3uMIbjAWB\n" +
            "A0dXvT6J6Jkwv5IAd20IAKgjatGhRANCAASZQ4IMei45MkVhDySFjpD117Mz5fJs\n" +
            "H8uBtltHZzJPow3osNIOHLdNV43gRcgo5ge+uJsSoLvy00j9/XOKsAVO";

    private static final String PASSWORD = "password";

    @Test
    public void tlsDemo() throws Exception {
        // Output debug info.
//        System.setProperty("com.tencent.kona.ssl.debug", "all");

        // Just use SM2 curve for key share
        System.setProperty("com.tencent.kona.ssl.namedGroups", "curveSM2");

        // Add providers.
        TestUtils.addProviders();

        GrpcServer server = new GrpcServer();
        server.start();
        int port = server.server.getPort();
        System.out.println("port: " + port);

        ManagedChannel channel = NettyChannelBuilder
                .forAddress("localhost", port)
                .sslContext(createJdkContext(true))
                .build();
        try {
            GrpcClient client = new GrpcClient(channel);
            client.sendMessage("Who are your?");
        } finally {
            channel.shutdownNow().awaitTermination(3, TimeUnit.SECONDS);
        }
    }

    private static JdkSslContext createJdkContext(boolean isClient)
            throws Exception {
        return new JdkSslContext(
                createContext(),
                isClient,
                Arrays.asList("TLS_SM4_GCM_SM3"),
                new AllAllowedCipherSuiteFilter(),
                new ApplicationProtocolConfig(
                        ApplicationProtocolConfig.Protocol.ALPN,
                        ApplicationProtocolConfig.SelectorFailureBehavior.FATAL_ALERT,
                        ApplicationProtocolConfig.SelectedListenerFailureBehavior.FATAL_ALERT,
                        "h2", "HTTP/1.1"),
                ClientAuth.NONE,
                new String[] {"TLSv1.3"},
                false);
    }

    private static SSLContext createContext() throws Exception {
        KeyStore trustStore = createTrustStore(CA, null);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", "KonaSSL");
        tmf.init(trustStore);

        KeyStore keyStore = createKeyStore(EE, EE_ID, EE_KEY);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509", "KonaSSL");
        kmf.init(keyStore, PASSWORD.toCharArray());

        SSLContext context = SSLContext.getInstance("TLS", "KonaSSL");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        return context;
    }

    private static KeyStore createTrustStore(String caStr, String caId)
            throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12", "KonaPKIX");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("tls-trust-demo", loadCert(caStr, caId));
        return trustStore;
    }

    private static KeyStore createKeyStore(
            String eeStr, String eeId, String eeKeyStr)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "KonaPKIX");
        keyStore.load(null, null);

        PrivateKey privateKey = loadPrivateKey(eeKeyStr);
        keyStore.setKeyEntry("tls-ee-demo",
                privateKey,
                PASSWORD.toCharArray(),
                new Certificate[] { loadCert(eeStr, eeId) } );

        return keyStore;
    }

    private static X509Certificate loadCert(String certPEM, String id)
            throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "KonaPKIX");
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
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "KonaCrypto");
        return keyFactory.generatePrivate(privateKeySpec);
    }

    private static class GrpcServer {

        private Server server;

        private void start() throws Exception {
            server = NettyServerBuilder
                    .forPort(0)
                    .sslContext(createJdkContext(false))
                    .addService(new MessageServiceImpl(this))
                    .build()
                    .start();

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("Shutting down server since JVM is shutting down");
                try {
                    stop();
                } catch (InterruptedException e) {
                    e.printStackTrace(System.err);
                }
                System.out.println("Server shut down");
            }));
        }

        private void stop() throws InterruptedException {
            if (server != null) {
                server.shutdown().awaitTermination(3, TimeUnit.SECONDS);
            }
        }

        private void blockUntilShutdown() throws InterruptedException {
            if (server != null) {
                server.awaitTermination();
            }
        }
    }

    private static class MessageServiceImpl
            extends MessageServiceGrpc.MessageServiceImplBase {

        private final GrpcServer server;

        private MessageServiceImpl(GrpcServer server) {
            this.server = server;
        }

        @Override
        public void sendMessage(MessageRequest req,
                StreamObserver<MessageResponse> responseObserver) {
            System.out.println("Request: " + req.getRequest());

            MessageResponse response = MessageResponse.newBuilder()
                    .setResponse("I'm server.")
                    .build();
            responseObserver.onNext(response);
            responseObserver.onCompleted();

            try {
                server.stop();
            } catch (InterruptedException e) {
                e.printStackTrace(System.out);
            }
        }
    }

    private static class GrpcClient {

        private final MessageServiceGrpc.MessageServiceBlockingStub blockingStub;

        public GrpcClient(Channel channel) {
            blockingStub = MessageServiceGrpc.newBlockingStub(channel);
        }

        public void sendMessage(String message) {
            MessageRequest request = MessageRequest.newBuilder()
                    .setRequest(message).build();
            MessageResponse response = null;
            try {
                response = blockingStub.sendMessage(request);
            } catch (StatusRuntimeException e) {
                e.printStackTrace(System.out);
                return;
            }
            System.out.println("Response: " + response.getResponse());
        }
    }

    private static class AllAllowedCipherSuiteFilter implements CipherSuiteFilter {

        @Override
        public String[] filterCipherSuites(Iterable<String> ciphers,
                List<String> defaultCiphers, Set<String> supportedCiphers) {
            return StreamSupport.stream(ciphers.spliterator(), false)
                    .toArray(String[]::new);
        }
    }
}
