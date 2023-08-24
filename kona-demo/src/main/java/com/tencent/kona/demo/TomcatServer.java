package com.tencent.kona.demo;

import com.tencent.kona.KonaProvider;
import com.tencent.kona.pkix.PKIXInsts;
import com.tencent.kona.ssl.SSLInsts;
import org.apache.catalina.Context;
import org.apache.catalina.connector.Connector;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLUtil;
import org.apache.tomcat.util.net.SSLUtilBase;
import org.apache.tomcat.util.net.jsse.JSSEImplementation;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.util.ResourceUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

//@SpringBootApplication
public class TomcatServer {

    static {
        Security.addProvider(new KonaProvider());
    }

    public static void main(String[] args) {
//        System.setProperty("com.tencent.kona.ssl.debug", "all");
//        SpringApplication.run(TomcatServer.class, args);
        new SpringApplicationBuilder(AppConfig.class)
                .child(TomcatServer.class)
                .run(args);
    }

    @RestController
    public static class ResponseController {

        @GetMapping("/tomcat")
        public String response() {
            return "This is a testing server on Tencent Kona SM Suite";
        }
    }

    @Bean
    public TomcatServletWebServerFactory webServerFactory(AppConfig appConfig)
            throws CertificateException, KeyStoreException, IOException,
            NoSuchAlgorithmException {
        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory() {

            @Override
            protected void postProcessContext(Context context) {
                SecurityConstraint securityConstraint = new SecurityConstraint();
                securityConstraint.setUserConstraint("CONFIDENTIAL");
                SecurityCollection collection = new SecurityCollection();
                collection.addPattern("/*");
                securityConstraint.addCollection(collection);
                context.addConstraint(securityConstraint);
            }
        };
        tomcat.addAdditionalTomcatConnectors(httpsConnector(appConfig));
        return tomcat;
    }

    private Connector httpsConnector(AppConfig appConfig)
            throws CertificateException, KeyStoreException, IOException,
            NoSuchAlgorithmException {
        Connector connector = new Connector(
                TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
        connector.setScheme("https");
        connector.setProperty("SSLEnabled", Boolean.toString(appConfig.isSslEnabled()));
        connector.setProperty("sslImplementationName", KonaSSLImpl.class.getName());
        connector.setPort(appConfig.getPort());

        SSLHostConfig sslConfig = new KonaSSLHostConfig();
        SSLHostConfigCertificate certConfig = new SSLHostConfigCertificate(
                sslConfig, SSLHostConfigCertificate.Type.EC);
        certConfig.setCertificateKeystore(createKeyStore(
                appConfig.getKeyStoreType(), appConfig.getKeyStorePath(),
                appConfig.getKeyStorePassword().toCharArray()));
        certConfig.setCertificateKeystorePassword(appConfig.getKeyStorePassword());
        sslConfig.addCertificate(certConfig);
        sslConfig.setTrustStore(createKeyStore(
                appConfig.getTrustStoreType(), appConfig.getTrustStorePath(),
                appConfig.getTrustStorePassword().toCharArray()));
        connector.addSslHostConfig(sslConfig);

        return connector;
    }

    private static KeyStore createKeyStore(
            String storeType, String storePath, char[] password)
            throws KeyStoreException, IOException, CertificateException,
            NoSuchAlgorithmException {
        KeyStore keyStore = PKIXInsts.getKeyStore(storeType);
        try (InputStream in = new FileInputStream(
                ResourceUtils.getFile(storePath))) {
            keyStore.load(in, password);
        }

        return keyStore;
    }

    public static class KonaSSLHostConfig extends SSLHostConfig {

        private static final long serialVersionUID = 3931709572625017292L;

        private Set<String> protocols;
        private List<String> ciphersuites;

        @Override
        public Set<String> getProtocols() {
            if (protocols == null) {
                protocols = new HashSet<>();
                protocols.add("TLCPv1.1");
                protocols.add("TLSv1.3");
            }

            return protocols;
        }

        @Override
        public List<String> getJsseCipherNames() {
            if (ciphersuites == null) {
                ciphersuites = Collections.unmodifiableList(Arrays.asList(
                        "TLCP_ECC_SM4_GCM_SM3",
                        "TLCP_ECC_SM4_CBC_SM3",
                        "TLCP_ECDHE_SM4_GCM_SM3",
                        "TLCP_ECDHE_SM4_CBC_SM3",
                        "TLS_SM4_GCM_SM3",
                        "TLS_AES_128_GCM_SHA256"));
            }

            return ciphersuites;
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

        private Set<String> protocols;
        private Set<String> ciphersuites;

        public KonaSSLUtil(SSLHostConfigCertificate certificate) {
            super(certificate);
        }

        public KonaSSLUtil(SSLHostConfigCertificate certificate,
                           boolean warnTls13) {
            super(certificate, warnTls13);
        }

        @Override
        public KeyManager[] getKeyManagers() throws Exception {
            KeyManagerFactory kmf = SSLInsts.getKeyManagerFactory("NewSunX509");
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
            if (protocols == null) {
                protocols = new HashSet<>();
                protocols.add("TLCPv1.1");
                protocols.add("TLSv1.3");
            }

            return protocols;
        }

        @Override
        protected Set<String> getImplementedCiphers() {
            if (ciphersuites == null) {
                Set<String> temp = new HashSet<>();
                temp.add("TLCP_ECC_SM4_GCM_SM3");
                temp.add("TLCP_ECC_SM4_CBC_SM3");
                temp.add("TLCP_ECDHE_SM4_GCM_SM3");
                temp.add("TLCP_ECDHE_SM4_CBC_SM3");
                temp.add("TLS_SM4_GCM_SM3");
                temp.add("TLS_AES_128_GCM_SHA256");

                ciphersuites = Collections.unmodifiableSet(temp);
            }

            return ciphersuites;
        }

        @Override
        protected boolean isTls13RenegAuthAvailable() {
            // TLS 1.3 does not support authentication after the initial handshake
            return false;
        }

        @Override
        public org.apache.tomcat.util.net.SSLContext createSSLContextInternal(
                List<String> negotiableProtocols) throws NoSuchAlgorithmException {
            return new KonaSSLContext(sslHostConfig.getSslProtocol());
        }
    }

    public static class KonaSSLContext
            implements org.apache.tomcat.util.net.SSLContext {

        private final SSLContext context;
        private KeyManager[] kms;
        private TrustManager[] tms;

        public KonaSSLContext(String protocol) throws NoSuchAlgorithmException {
            context = SSLInsts.getSSLContext(protocol);
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
}
