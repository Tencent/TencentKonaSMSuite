package com.tencent.kona.ssl.peers;

import com.tencent.kona.crypto.KonaCryptoProvider;
import com.tencent.kona.pkix.KonaPKIXProvider;
import com.tencent.kona.ssl.KonaSSLProvider;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.CipherSuiteFilter;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.JdkSslContext;
import io.netty.handler.ssl.SslContext;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.stream.StreamSupport;

/**
 * A Netty-based Echo client on TLCP.
 */
public class TLCPNettyClient {

    private static final String CA =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBjDCCATKgAwIBAgIUc1kBltJcsvucxFYD+CzKcGvuNHowCgYIKoEcz1UBg3Uw\n" +
            "EjEQMA4GA1UEAwwHdGxjcC1jYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgxMTU2\n" +
            "MzhaMBUxEzARBgNVBAMMCnRsY3AtaW50Y2EwWTATBgcqhkjOPQIBBggqgRzPVQGC\n" +
            "LQNCAAS1g0eBwqPefYRBc2zyZlJi6jyfF7RlsFspKwF5LMxkcYMblZXjlUYVhnpN\n" +
            "F3N/x2knleNfrXrdTTR3Yv2MIMGQo2MwYTAdBgNVHQ4EFgQURS/dNZJ+d0Sel9TW\n" +
            "vGNYGWnxTb4wHwYDVR0jBBgwFoAUQI8lwKZzxP/OpobF4UNyPG3JiocwDwYDVR0T\n" +
            "AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwCgYIKoEcz1UBg3UDSAAwRQIhAI79\n" +
            "0T0rhbYCdqdGqbYxidgyr1XRpXncwRqmx7a+IDkvAiBDPtfFfB/UiwO4wBLqxwJO\n" +
            "+xEdTF+d/Wfro9fxSnrqEw==\n" +
            "-----END CERTIFICATE-----";

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
    private static final String SIGN_EE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg6wAH+egoZkKS3LKi\n" +
            "0okzJSYrn/yRVhNfmdhySuJic5ahRANCAARYT1t4ecS5pLkQlA9smyxe1tictMdl\n" +
            "/x4AbO8nI07CHjXKHPhtPzJLvKFH2qqQTZmn4LnfLqaPgGjx8ymqRuOD";

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
    private static final String ENC_EE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgqFilR+zUyRQWREb+\n" +
            "rb5uIldK/bPE1l20DzNpuMt55VehRANCAAQEG2rW9d4CS987dQfFOS6IXkSfuF50\n" +
            "aaiEOTrMdFQ5OFFtufGi5VPem396J75x04aWvRsB22OQaWLDD9YUvtZA";

    private static final String PASSWORD = "password";

    private static final String HOST = System.getProperty(
            "com.tencent.kona.ssl.demo.host", "127.0.0.1");
    private static final int PORT = Integer.getInteger(
            "com.tencent.kona.ssl.demo.port", 7443);
    private static final int SIZE = Integer.getInteger(
            "com.tencent.kona.ssl.demo.size", 256);

    public static void main(String[] args) throws Exception {
        System.setProperty("com.tencent.kona.ssl.debug", "all");

        addProviders();

        // Configure SSL.git
        final SslContext sslCtx = createJdkContext();

        // Configure the client.
        EventLoopGroup group = new NioEventLoopGroup();
        try {
            Bootstrap b = new Bootstrap();
            b.group(group)
             .channel(NioSocketChannel.class)
             .option(ChannelOption.TCP_NODELAY, true)
             .handler(new ChannelInitializer<SocketChannel>() {
                 @Override
                 public void initChannel(SocketChannel ch) throws Exception {
                     ChannelPipeline p = ch.pipeline();
                     p.addLast(sslCtx.newHandler(ch.alloc(), HOST, PORT));
                     //p.addLast(new LoggingHandler(LogLevel.INFO));
                     p.addLast(new EchoClientHandler());
                 }
             });

            // Start the client.
            ChannelFuture f = b.connect(HOST, PORT).sync();

            // Wait until the connection is closed.
            f.channel().closeFuture().sync();
        } finally {
            // Shut down the event loop to terminate all threads.
            group.shutdownGracefully();
        }
    }

    private static void addProviders() {
        Security.addProvider(new KonaCryptoProvider());
        Security.addProvider(new KonaPKIXProvider());
        Security.addProvider(new KonaSSLProvider());
    }

    private static JdkSslContext createJdkContext()
            throws Exception {
        return new JdkSslContext(
                createContext(),
                true,
                Arrays.asList("TLCP_ECC_SM4_GCM_SM3", "TLCP_ECC_SM4_CBC_SM3"),
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

    private static class AllAllowedCipherSuiteFilter implements CipherSuiteFilter {

        @Override
        public String[] filterCipherSuites(Iterable<String> ciphers,
                List<String> defaultCiphers, Set<String> supportedCiphers) {
            return StreamSupport.stream(ciphers.spliterator(), false)
                    .toArray(String[]::new);
        }
    }

    private static SSLContext createContext() throws Exception {
        KeyStore trustStore = createTrustStore(CA, null);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", "KonaSSL");
        tmf.init(trustStore);

        KeyStore keyStore = createKeyStore(
                SIGN_EE, SIGN_EE_KEY, ENC_EE, ENC_EE_KEY);
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
        trustStore.setCertificateEntry("tlcp-trust-demo", loadCert(caStr));
        return trustStore;
    }

    private static KeyStore createKeyStore(
            String signEeStr, String signEeKeyStr,
            String encEeStr, String encEeKeyStr)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "KonaPKIX");
        keyStore.load(null, null);

        keyStore.setKeyEntry("tlcp-sign-ee-demo",
                loadPrivateKey(signEeKeyStr),
                PASSWORD.toCharArray(),
                new Certificate[] { loadCert(signEeStr) } );
        keyStore.setKeyEntry("tlcp-enc-ee-demo",
                loadPrivateKey(encEeKeyStr),
                PASSWORD.toCharArray(),
                new Certificate[] { loadCert(encEeStr) } );

        return keyStore;
    }

    private static X509Certificate loadCert(String certPEM)
            throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance(
                "X.509", "KonaPKIX");
        return (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(certPEM.getBytes()));
    }

    private static PrivateKey loadPrivateKey(String keyPEM) throws Exception {
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                Base64.getMimeDecoder().decode(keyPEM));
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "KonaCrypto");
        return keyFactory.generatePrivate(privateKeySpec);
    }

    private static class EchoClientHandler extends ChannelInboundHandlerAdapter {

        private static final String MESSAGE = System.getProperty(
                "com.tencent.kona.ssl.demo", "Hello");

        private final ByteBuf message = message();

        private static ByteBuf message() {
            byte[] message = "Hello".getBytes(StandardCharsets.UTF_8);
            ByteBuf messageBuf = Unpooled.buffer(message.length);
            messageBuf.writeBytes(message);
            return messageBuf;
        }

        @Override
        public void channelActive(ChannelHandlerContext ctx) {
            ctx.writeAndFlush(message);
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            ctx.write(msg);
        }

        @Override
        public void channelReadComplete(ChannelHandlerContext ctx) {
           ctx.flush();
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            // Close the connection when an exception is raised.
            cause.printStackTrace();
            ctx.close();
        }
    }
}
