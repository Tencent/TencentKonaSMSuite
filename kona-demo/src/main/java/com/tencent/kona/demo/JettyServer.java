package com.tencent.kona.demo;

import com.tencent.kona.KonaProvider;
import org.eclipse.jetty.alpn.server.ALPNServerConnectionFactory;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.http2.server.HTTP2ServerConnectionFactory;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.embedded.jetty.JettyServerCustomizer;
import org.springframework.boot.web.embedded.jetty.JettyServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.util.ResourceUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.net.ssl.SSLParameters;
import java.io.FileNotFoundException;
import java.security.Security;

@SpringBootApplication
public class JettyServer {

    static {
        Security.addProvider(new KonaProvider());
    }

    public static void main(String[] args) {
//        System.setProperty("com.tencent.kona.ssl.debug", "all");
        SpringApplication.run(JettyServer.class, args);
    }

    @Bean
    public ConfigurableServletWebServerFactory webServerFactory(AppConfig config) {
        JettyServletWebServerFactory factory = new JettyServletWebServerFactory();
        factory.addServerCustomizers(new ServerCustomizer(config));
        return factory;
    }

    @RestController
    public static class ResponseController {

        @GetMapping("/jetty")
        public String response() {
            return "This is a testing server on Tencent Kona SM Suite";
        }
    }

    public static class ServerCustomizer implements JettyServerCustomizer {

        private static final String[] APP_PROTOCOLS = new String[] {"h2", "HTTP/1.1"};

        private final AppConfig appConfig;

        public ServerCustomizer(AppConfig appConfig) {
            this.appConfig = appConfig;
        }

        @Override
        public void customize(Server server) {
            SslContextFactory.Server contextFactory = new SslContextFactory.Server() {

                @Override
                public SSLParameters customize(SSLParameters sslParams) {
                    if (appConfig.isHttp2Enabled()) {
                        // This configuration does work in the application protocol negotiation.
                        sslParams.setApplicationProtocols(APP_PROTOCOLS);
                    }
                    return super.customize(sslParams);
                }
            };

            contextFactory.setTrustStoreProvider(appConfig.getTrustStoreProvider());
            contextFactory.setTrustStoreType(appConfig.getTrustStoreType());
            contextFactory.setTrustStorePath(getAbsolutePath(appConfig.getTrustStorePath()));
            contextFactory.setTrustStorePassword(appConfig.getTrustStorePassword());

            contextFactory.setKeyStoreProvider(appConfig.getKeyStoreProvider());
            contextFactory.setKeyStoreType(appConfig.getKeyStoreType());
            contextFactory.setKeyStorePath(getAbsolutePath(appConfig.getKeyStorePath()));
            contextFactory.setKeyStorePassword(appConfig.getKeyStorePassword());
            contextFactory.setKeyManagerPassword(appConfig.getKeyStorePassword());

            contextFactory.setProtocol(appConfig.getContextProtocol());

            HttpConfiguration httpsConfig = new HttpConfiguration();
            httpsConfig.setSecureScheme("https");
            httpsConfig.addCustomizer(new SecureRequestCustomizer());

            ServerConnector httpsConnector;
            if (appConfig.isHttp2Enabled()) {
                // This configuration just takes the server to enable the
                // modules alpn and h2 and display the hints like the below,
                // Started ServerConnector@17d32e9b{SSL, (ssl, alpn, h2, http/1.1)}{0.0.0.0:8443}
                //
                // But it does not work in the application protocol negotiation.
                httpsConnector = new ServerConnector(
                    server,
                    new SslConnectionFactory(contextFactory,
                            HttpVersion.HTTP_1_1.asString()),
                    new ALPNServerConnectionFactory(APP_PROTOCOLS),
                    new HTTP2ServerConnectionFactory(httpsConfig),
                    new HttpConnectionFactory(httpsConfig));
            } else {
                httpsConnector = new ServerConnector(
                    server,
                    new SslConnectionFactory(contextFactory,
                            HttpVersion.HTTP_1_1.asString()),
                    new HttpConnectionFactory(httpsConfig));
            }

            httpsConnector.setPort(appConfig.getPort());

            server.setConnectors(new Connector[] { httpsConnector });
            server.setStopAtShutdown(true);
        }

        private static String getAbsolutePath(String resourcePath) {
            try {
                return ResourceUtils.getFile(resourcePath).getAbsolutePath();
            } catch (FileNotFoundException e) {
                // Should not occur
                throw new IllegalStateException("Not found: " + resourcePath, e);
            }
        }
    }
}
