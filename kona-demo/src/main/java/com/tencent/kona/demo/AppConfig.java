package com.tencent.kona.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Value("${server.port}")
    private int port;

    @Value("${server.ssl.trust-store-provider}")
    private String trustStoreProvider;

    @Value("${server.ssl.trust-store-type}")
    private String trustStoreType;

    @Value("${server.ssl.trust-store}")
    private String trustStorePath;

    @Value("${server.ssl.trust-store-password}")
    private String trustStorePassword;

    @Value("${server.ssl.key-store-provider}")
    private String keyStoreProvider;

    @Value("${server.ssl.key-store-type}")
    private String keyStoreType;

    @Value("${server.ssl.key-store}")
    private String keyStorePath;

    @Value("${server.ssl.key-store-password}")
    private String keyStorePassword;

    @Value("${server.ssl.protocol}")
    private String contextProtocol;

    @Value("${server.http2.enabled}")
    private boolean http2Enabled;

    public int getPort() {
        return port;
    }

    public void setPort(String port) {
        this.port = Integer.parseInt(port);
    }

    public String getTrustStoreProvider() {
        return trustStoreProvider;
    }

    public void setTrustStoreProvider(String trustStoreProvider) {
        this.trustStoreProvider = trustStoreProvider;
    }

    public String getTrustStoreType() {
        return trustStoreType;
    }

    public void setTrustStoreType(String trustStoreType) {
        this.trustStoreType = trustStoreType;
    }

    public String getTrustStorePath() {
        return trustStorePath;
    }

    public void setTrustStorePath(String trustStorePath) {
        this.trustStorePath = trustStorePath;
    }

    public String getTrustStorePassword() {
        return trustStorePassword;
    }

    public void setTrustStorePassword(String trustStorePassword) {
        this.trustStorePassword = trustStorePassword;
    }

    public String getKeyStoreProvider() {
        return keyStoreProvider;
    }

    public void setKeyStoreProvider(String keyStoreProvider) {
        this.keyStoreProvider = keyStoreProvider;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    public String getKeyStorePath() {
        return keyStorePath;
    }

    public void setKeyStorePath(String keyStorePath) {
        this.keyStorePath = keyStorePath;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public String getContextProtocol() {
        return contextProtocol;
    }

    public void setContextProtocol(String contextProtocol) {
        this.contextProtocol = contextProtocol;
    }

    public boolean isHttp2Enabled() {
        return http2Enabled;
    }

    public void setHttp2Enabled(String http2Enabled) {
        this.http2Enabled = Boolean.parseBoolean(http2Enabled);
    }
}
