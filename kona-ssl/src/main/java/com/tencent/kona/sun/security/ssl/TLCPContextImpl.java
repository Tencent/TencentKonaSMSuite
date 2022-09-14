package com.tencent.kona.sun.security.ssl;

import java.util.ArrayList;
import java.util.List;

/**
 * Implementations of SSLContext for TLCP.
 */
public final class TLCPContextImpl {

    public static final class TLCP11Context
            extends SSLContextImpl.AbstractTLSContext {

        private static final List<ProtocolVersion> serverDefaultProtocols;
        private static final List<CipherSuite> serverDefaultCipherSuites;

        private static final List<ProtocolVersion> clientDefaultProtocols;
        private static final List<CipherSuite> clientDefaultCipherSuites;

        static {
            serverDefaultProtocols = getAvailableProtocols(
                    new ProtocolVersion[] {
                ProtocolVersion.TLCP11,
            });
            clientDefaultProtocols = getAvailableProtocols(
                    new ProtocolVersion[] {
                ProtocolVersion.TLCP11,
            });

            serverDefaultCipherSuites = getApplicableEnabledCipherSuites(
                    clientDefaultProtocols, true);
            clientDefaultCipherSuites = getApplicableEnabledCipherSuites(
                    clientDefaultProtocols, true);
        }

        @Override
        List<ProtocolVersion> getServerDefaultProtocolVersions() {
            return serverDefaultProtocols;
        }

        @Override
        List<CipherSuite> getServerDefaultCipherSuites() {
            return serverDefaultCipherSuites;
        }

        @Override
        List<ProtocolVersion> getClientDefaultProtocolVersions() {
            return clientDefaultProtocols;
        }

        @Override
        List<CipherSuite> getClientDefaultCipherSuites() {
            return clientDefaultCipherSuites;
        }
    }

    public static final class TLCPContext
            extends SSLContextImpl.AbstractTLSContext {

        private static final List<ProtocolVersion> serverDefaultProtocols;
        private static final List<CipherSuite> serverDefaultCipherSuites;

        private static final List<ProtocolVersion> clientDefaultProtocols;
        private static final List<CipherSuite> clientDefaultCipherSuites;

        private static final IllegalArgumentException reservedException;

        static {
            reservedException = CustomizedSSLProtocols.reservedException;
            if (reservedException == null) {
                clientDefaultProtocols = customizedProtocols(true,
                        CustomizedSSLProtocols.customizedClientProtocols);
                serverDefaultProtocols = customizedProtocols(false,
                        CustomizedSSLProtocols.customizedServerProtocols);

                clientDefaultCipherSuites =
                        getApplicableEnabledCipherSuites(
                                clientDefaultProtocols, true);
                serverDefaultCipherSuites =
                        getApplicableEnabledCipherSuites(
                                serverDefaultProtocols, false);
            } else {
                // unlikely to be used
                clientDefaultProtocols = null;
                serverDefaultProtocols = null;
                clientDefaultCipherSuites = null;
                serverDefaultCipherSuites = null;
            }
        }

        private static List<ProtocolVersion> customizedProtocols(
                boolean client, List<ProtocolVersion> customized) {
            List<ProtocolVersion> refactored = new ArrayList<>();
            for (ProtocolVersion pv : customized) {
                if (!pv.isDTLS) {
                    refactored.add(pv);
                }
            }

            // Use the default enabled protocols if no customization
            ProtocolVersion[] candidates;
            if (refactored.isEmpty()) {
                // Client and server use the same default protocols.
                candidates = new ProtocolVersion[] {
                        ProtocolVersion.TLCP11,
                        ProtocolVersion.TLS13,
                        ProtocolVersion.TLS12,
                        ProtocolVersion.TLS11,
                        ProtocolVersion.TLS10
                    };
            } else {
                // Use the customized TLS protocols.
                candidates =
                    refactored.toArray(new ProtocolVersion[0]);
            }

            return getAvailableProtocols(candidates);
        }

        @Override
        List<ProtocolVersion> getServerDefaultProtocolVersions() {
            return serverDefaultProtocols;
        }

        @Override
        List<CipherSuite> getServerDefaultCipherSuites() {
            return serverDefaultCipherSuites;
        }

        @Override
        List<ProtocolVersion> getClientDefaultProtocolVersions() {
            return clientDefaultProtocols;
        }

        @Override
        List<CipherSuite> getClientDefaultCipherSuites() {
            return clientDefaultCipherSuites;
        }
    }
}
