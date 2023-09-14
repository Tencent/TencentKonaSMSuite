package com.tencent.kona.ssl.demo;

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.pkix.PKIXInsts;
import com.tencent.kona.ssl.SSLInsts;
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
 * A comprehensive demo for TLCP with gRPC.
 */
public class TLCPWithGRPCDemo {

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
                Arrays.asList("TLCP_ECC_SM4_CBC_SM3"),
                new AllAllowedCipherSuiteFilter(),
                new ApplicationProtocolConfig(
                        ApplicationProtocolConfig.Protocol.ALPN,
                        ApplicationProtocolConfig.SelectorFailureBehavior.FATAL_ALERT,
                        ApplicationProtocolConfig.SelectedListenerFailureBehavior.FATAL_ALERT,
                        "h2", "HTTP/1.1"),
                ClientAuth.NONE,
                new String[] {"TLCPv1.1"},
                false);
    }

    private static SSLContext createContext() throws Exception {
        KeyStore trustStore = createTrustStore(CA, null);
        TrustManagerFactory tmf = SSLInsts.getTrustManagerFactory("PKIX");
        tmf.init(trustStore);

        KeyStore keyStore = createKeyStore(
                SIGN_EE, SIGN_EE_ID, SIGN_EE_KEY,
                ENC_EE, ENC_EE_ID, ENC_EE_KEY);
        KeyManagerFactory kmf = SSLInsts.getKeyManagerFactory("NewSunX509");
        kmf.init(keyStore, PASSWORD.toCharArray());

        SSLContext context = SSLInsts.getSSLContext("TLCPv1.1");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        return context;
    }

    private static KeyStore createTrustStore(String caStr, String caId)
            throws Exception {
        KeyStore trustStore = PKIXInsts.getKeyStore("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("tlcp-trust-demo", loadCert(caStr, caId));
        return trustStore;
    }

    private static KeyStore createKeyStore(
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

        return keyStore;
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
