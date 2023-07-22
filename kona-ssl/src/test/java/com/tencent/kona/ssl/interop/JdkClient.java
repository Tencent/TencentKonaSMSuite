/*
 * Copyright (c) 2020, 2022, Oracle and/or its affiliates. All rights reserved.
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

package com.tencent.kona.ssl.interop;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/*
 * A JDK client based on SSLSocket.
 */
public class JdkClient extends AbstractClient {

    public final int timeout;
    public final String request;
    public final boolean readResponse;

    public final ConnectionInterceptor interceptor;
    public final SSLContext context;
    public final SSLSocket socket;

    public JdkClient(Builder builder) throws Exception {
        timeout = builder.getTimeout() * 1000;
        request = builder.getMessage();
        readResponse = builder.isReadResponse();

        interceptor = builder.getInterceptor();

        NamedGroup[] namedGroups = builder.getNamedGroups();
        if (namedGroups != null) {
            System.setProperty("com.tencent.kona.ssl.namedGroups",
                    Utilities.join(",",
                            (namedGroup) -> namedGroup.name,
                            namedGroups));
        }

        SignatureScheme[] signatureSchemes = builder.getSignatureSchemes();
        if (signatureSchemes != null) {
            System.setProperty("com.tencent.kona.ssl.client.signatureSchemes",
                    Utilities.join(",",
                            (signatureScheme) -> signatureScheme.name,
                            signatureSchemes));
        }

        context = getContext(builder);
        socket = (SSLSocket) context.getSocketFactory().createSocket();
        configClientSocket(builder);
    }

    protected SSLContext getContext(Builder builder) throws Exception {
        return builder.getContext() == null
                ? Utilities.createSSLContext(builder.getProvider(),
                        builder.getContextProtocol(), builder.getCertTuple())
                : builder.getContext();
    }

    protected void configClientSocket(Builder builder) throws SocketException {
        socket.setSoTimeout(timeout);
        if (builder.getProtocols() != null) {
            socket.setEnabledProtocols(Utilities.enumsToStrs(protocol -> {
                return JdkUtils.protocol((Protocol) protocol);
            }, builder.getProtocols()));
        }
        if (builder.getCipherSuites() != null) {
            socket.setEnabledCipherSuites(
                    Utilities.enumsToStrs(builder.getCipherSuites()));
        }
        SSLParameters sslParams = socket.getSSLParameters();
        if (builder.getServerNames() != null) {
            List<SNIServerName> serverNames = new ArrayList<>();
            for(String bufServerName : builder.getServerNames()) {
                serverNames.add(new SNIHostName(bufServerName));
            }
            sslParams.setServerNames(serverNames);
        }
        if (builder.getAppProtocols() != null) {
            sslParams.setApplicationProtocols(builder.getAppProtocols());
        }
        socket.setSSLParameters(sslParams);
    }

    public static class Builder extends AbstractClient.Builder {

        private Provider provider = Provider.KONA;

        private ConnectionInterceptor interceptor;
        private SSLContext context;

        public Provider getProvider() {
            return provider;
        }

        public AbstractPeer.Builder setProvider(Provider provider) {
            this.provider = provider;
            return this;
        }

        public ConnectionInterceptor getInterceptor() {
            return interceptor;
        }

        public Builder setInterceptor(ConnectionInterceptor interceptor) {
            this.interceptor = interceptor;
            return this;
        }

        public SSLContext getContext() {
            return context;
        }

        public Builder setContext(SSLContext context) {
            this.context = context;
            return this;
        }

        @Override
        public JdkClient build() throws Exception {
            return new JdkClient(this);
        }
    }

    @Override
    public Product getProduct() {
        return Jdk.DEFAULT;
    }

    public SSLSession getSession() {
        return socket.getSession();
    }

    @Override
    public void connect(String host, int port) throws IOException {
        socket.connect(new InetSocketAddress(host, port), timeout);
        Utilities.writeOut(socket.getOutputStream(), request);
        if (Utilities.DEBUG) {
            System.out.println("Send request: " + request);
        }

        if (readResponse) {
            String response = Utilities.readIn(socket.getInputStream());
            if (Utilities.DEBUG) {
                System.out.println("Received response: " + response);
            }
        }

        if (interceptor != null) {
            interceptor.beforeExit(socket);
        }
    }

    @Override
    public String getNegoAppProtocol() throws SSLTestException {
        return socket.getApplicationProtocol();
    }

    public void close() throws IOException {
        if (!socket.isClosed()) {
            socket.close();
        }
    }
}
