package com.tencent.kona.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import javax.security.auth.x500.X500Principal;

final class TLCPCertificateRequest {

    static final SSLConsumer tlcpHandshakeConsumer
            = new TLCPCertificateRequestConsumer();
    static final HandshakeProducer tlcpHandshakeProducer
            = new TLCPCertificateRequestProducer();

    private static final class TLCPCertificateRequestMessage
            extends SSLHandshake.HandshakeMessage {

        final byte[] types;                 // certificate types
        final int[] algorithmIds;           // supported signature algorithms
        final List<byte[]> authorities;     // certificate authorities

        TLCPCertificateRequestMessage(HandshakeContext handshakeContext,
                    X509Certificate[] trustedCerts, CipherSuite.KeyExchange keyExchange,
                    List<SignatureScheme> signatureSchemes) throws IOException {
            super(handshakeContext);

            this.types = new byte[] {
                    CertificateRequest.ClientCertificateType.ECDSA_SIGN.id,
                    CertificateRequest.ClientCertificateType.RSA_SIGN.id};

            if (handshakeContext.negotiatedProtocol.isTLS12()) {
                if (signatureSchemes == null || signatureSchemes.isEmpty()) {
                    throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                            "No signature algorithms specified for " +
                                    "CertificateRequest hanshake message");
                }
                this.algorithmIds = new int[signatureSchemes.size()];
                int i = 0;
                for (SignatureScheme scheme : signatureSchemes) {
                    algorithmIds[i++] = scheme.id;
                }
            } else {
                algorithmIds = new int[0];
            }

            this.authorities = new ArrayList<>(trustedCerts.length);
            for (X509Certificate cert : trustedCerts) {
                X500Principal x500Principal = cert.getSubjectX500Principal();
                authorities.add(x500Principal.getEncoded());
            }
        }

        TLCPCertificateRequestMessage(HandshakeContext handshakeContext,
                ByteBuffer m) throws IOException {
            super(handshakeContext);

            // struct {
            //     ClientCertificateType certificate_types<1..2^8-1>;
            //     SignatureAndHashAlgorithm
            //       supported_signature_algorithms<2..2^16-2>;
            //     DistinguishedName certificate_authorities<0..2^16-1>;
            // } CertificateRequest;

            // certificate_authorities
            int minLen = handshakeContext.negotiatedProtocol.isTLCP11() ? 4 : 8;
            if (m.remaining() < minLen) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                        "Invalid CertificateRequest handshake message: " +
                        "no sufficient data");
            }
            this.types = Record.getBytes8(m);

            if (handshakeContext.negotiatedProtocol.isTLS12()) {
                // supported_signature_algorithms
                if (m.remaining() < 6) {
                    throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                            "Invalid CertificateRequest handshake message: " +
                                    "no sufficient data");
                }

                byte[] algs = Record.getBytes16(m);
                if (algs.length == 0 || (algs.length & 0x01) != 0) {
                    throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                            "Invalid CertificateRequest handshake message: " +
                                    "incomplete signature algorithms");
                }

                this.algorithmIds = new int[(algs.length >> 1)];
                for (int i = 0, j = 0; i < algs.length; ) {
                    byte hash = algs[i++];
                    byte sign = algs[i++];
                    algorithmIds[j++] = ((hash & 0xFF) << 8) | (sign & 0xFF);
                }
            } else {
                this.algorithmIds = new int[0];
            }

            // certificate_authorities
            if (m.remaining() < 2) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                        "Invalid CertificateRequest handshake message: " +
                        "no sufficient data");
            }

            int listLen = Record.getInt16(m);
            if (listLen > m.remaining()) {
                throw handshakeContext.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Invalid CertificateRequest message: no sufficient data");
            }

            if (listLen > 0) {
                this.authorities = new LinkedList<>();
                while (listLen > 0) {
                    // opaque DistinguishedName<1..2^16-1>;
                    byte[] encoded = Record.getBytes16(m);
                    listLen -= (2 + encoded.length);
                    authorities.add(encoded);
                }
            } else {
                this.authorities = Collections.emptyList();
            }
        }

        String[] getKeyTypes() {
            return CertificateRequest.ClientCertificateType.getKeyTypes(types);
        }

        X500Principal[] getAuthorities() {
            X500Principal[] principals = new X500Principal[authorities.size()];
            int i = 0;
            for (byte[] encoded : authorities) {
                principals[i++] = new X500Principal(encoded);
            }

            return principals;
        }

        @Override
        public SSLHandshake handshakeType() {
            return SSLHandshake.CERTIFICATE_REQUEST;
        }

        @Override
        public int messageLength() {
            int len = 1 + types.length + 2;
            if (algorithmIds.length > 0) {
                 len += (algorithmIds.length << 1) + 2;
            }
            for (byte[] encoded : authorities) {
                len += encoded.length + 2;
            }
            return len;
        }

        @Override
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putBytes8(types);

            int listLen = 0;
            for (byte[] encoded : authorities) {
                listLen += encoded.length + 2;
            }

            hos.putInt16(listLen);
            for (byte[] encoded : authorities) {
                hos.putBytes16(encoded);
            }
        }

        @Override
        public String toString() {
            MessageFormat messageFormat = new MessageFormat(
                    "\"CertificateRequest\": '{'\n" +
                    "  \"certificate types\": {0}\n" +
                    "  \"supported signature algorithms\": {1}\n" +
                    "  \"certificate authorities\": {2}\n" +
                    "'}'",
                    Locale.ENGLISH);

            List<String> typeNames = new ArrayList<>(types.length);
            for (byte type : types) {
                typeNames.add(CertificateRequest.ClientCertificateType.nameOf(type));
            }

            List<String> algorithmNames = new ArrayList<>(algorithmIds.length);
            for (int algorithmId : algorithmIds) {
                algorithmNames.add(SignatureScheme.nameOf(algorithmId));
            }

            List<String> authorityNames = new ArrayList<>(authorities.size());
            for (byte[] encoded : authorities) {
                X500Principal principal = new X500Principal(encoded);
                authorityNames.add(principal.toString());
            }
            Object[] messageFields = {
                typeNames,
                algorithmNames,
                authorityNames
            };

            return messageFormat.format(messageFields);
        }
    }

    private static final class TLCPCertificateRequestProducer
            implements HandshakeProducer {

        // Prevent instantiation of this class.
        private TLCPCertificateRequestProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                SSLHandshake.HandshakeMessage message) throws IOException {
            // The producing happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            List<SignatureScheme> localSupportedSignAlgs = null;
            if (shc.negotiatedProtocol.isTLS12()) {
                if (shc.localSupportedSignAlgs == null) {
                    shc.localSupportedSignAlgs =
                            SignatureScheme.getSupportedAlgorithms(
                                    shc.sslConfig,
                                    shc.algorithmConstraints, shc.activeProtocols);
                }

                if (shc.localSupportedSignAlgs.isEmpty()) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "No supported signature algorithm");
                }

                localSupportedSignAlgs = shc.localSupportedSignAlgs;
            }

            X509Certificate[] caCerts =
                    shc.sslContext.getX509TrustManager().getAcceptedIssuers();
            TLCPCertificateRequestMessage crm = new TLCPCertificateRequestMessage(
                    shc, caCerts, shc.negotiatedCipherSuite.keyExchange,
                    localSupportedSignAlgs);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                    "Produced CertificateRequest handshake message", crm);
            }

            // Output the handshake message.
            crm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();

            //
            // update
            //
            shc.handshakeConsumers.put(SSLHandshake.CERTIFICATE.id,
                    SSLHandshake.CERTIFICATE);
            shc.handshakeConsumers.put(SSLHandshake.CERTIFICATE_VERIFY.id,
                    SSLHandshake.CERTIFICATE_VERIFY);

            // The handshake message has been delivered.
            return null;
        }
    }

    private static final class TLCPCertificateRequestConsumer
            implements SSLConsumer {

        // Prevent instantiation of this class.
        private TLCPCertificateRequestConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                ByteBuffer message) throws IOException {
            // The consuming happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            // clean up this consumer
            chc.handshakeConsumers.remove(SSLHandshake.CERTIFICATE_REQUEST.id);
            chc.receivedCertReq = true;

            // If we're processing this message and the server's certificate
            // message consumer has not already run then this is a state
            // machine violation.
            if (chc.handshakeConsumers.containsKey(
                    SSLHandshake.CERTIFICATE.id)) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                        "Unexpected CertificateRequest handshake message");
            }

            SSLConsumer certStatCons = chc.handshakeConsumers.remove(
                    SSLHandshake.CERTIFICATE_STATUS.id);
            if (certStatCons != null) {
                // Stapling was active but no certificate status message
                // was sent.  We need to run the absence handler which will
                // check the certificate chain.
                CertificateStatus.handshakeAbsence.absent(context, null);
            }

            TLCPCertificateRequestMessage crm =
                    new TLCPCertificateRequestMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                        "Consuming CertificateRequest handshake message", crm);
            }

            //
            // validate
            //
            // blank

            //
            // update
            //

            // An empty client Certificate handshake message may be allow.
            chc.handshakeProducers.put(SSLHandshake.CERTIFICATE.id,
                    SSLHandshake.CERTIFICATE);

            if (chc.negotiatedProtocol.isTLS12()) {
                List<SignatureScheme> sss =
                        SignatureScheme.getSupportedAlgorithms(
                                chc.sslConfig,
                                chc.algorithmConstraints, chc.negotiatedProtocol,
                                crm.algorithmIds);
                if (sss.isEmpty()) {
                    throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "No supported signature algorithm");
                }

                chc.peerRequestedSignatureSchemes = sss;
                chc.peerRequestedCertSignSchemes = sss;     // use the same schemes
                chc.handshakeSession.setPeerSupportedSignatureAlgorithms(sss);
            }

            chc.peerSupportedAuthorities = crm.getAuthorities();

            // For TLS 1.2, we no longer use the certificate_types field
            // from the CertificateRequest message to directly determine
            // the SSLPossession.  Instead, the choosePossession method
            // will use the accepted signature schemes in the message to
            // determine the set of acceptable certificate types to select from.
            SSLPossession pos = chc.negotiatedProtocol.isTLCP11()
                    ? choosePossession4TLCP(chc)
                    : choosePossession(chc, crm);
            if (pos == null) {
                return;
            }

            chc.handshakePossessions.add(pos);
            chc.handshakeProducers.put(SSLHandshake.CERTIFICATE_VERIFY.id,
                    SSLHandshake.CERTIFICATE_VERIFY);
        }

        private static SSLPossession choosePossession4TLCP(HandshakeContext hc) {
            return TLCPAuthentication.createPossession(hc, new String[] {"EC"});
        }

        private static SSLPossession choosePossession(HandshakeContext hc,
                TLCPCertificateRequestMessage crm) throws IOException {
            if (hc.peerRequestedCertSignSchemes == null ||
                    hc.peerRequestedCertSignSchemes.isEmpty()) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("No signature and hash algorithms " +
                            "in CertificateRequest");
                }
                return null;
            }

            // Put the CR key type into a more friendly format for searching
            List<String> crKeyTypes = new ArrayList<>(
                    Arrays.asList(crm.getKeyTypes()));
            // For TLS 1.2 only if RSA is a requested key type then we
            // should also allow RSASSA-PSS.
            if (crKeyTypes.contains("RSA")) {
                crKeyTypes.add("RSASSA-PSS");
            }

            String[] supportedKeyTypes = hc.peerRequestedCertSignSchemes
                    .stream()
                    .map(ss -> ss.keyAlgorithm)
                    .distinct()
                    .filter(ka -> SignatureScheme.getPreferableAlgorithm(   // Don't select a signature scheme unless
                            hc.algorithmConstraints,                        //  we will be able to produce
                            hc.peerRequestedSignatureSchemes,               //  a CertificateVerify message later
                            ka, hc.negotiatedProtocol) != null
                            || SSLLogger.logWarning("ssl,handshake",
                                    "Unable to produce CertificateVerify for key algorithm: " + ka))
                    .filter(ka -> {
                        X509Authentication xa = X509Authentication.valueOfKeyAlgorithm(ka);
                        // Any auth object will have a set of allowed key types.
                        // This set should share at least one common algorithm with
                        // the CR's allowed key types.
                        return xa != null && !Collections.disjoint(crKeyTypes, Arrays.asList(xa.keyTypes))
                                || SSLLogger.logWarning("ssl,handshake", "Unsupported key algorithm: " + ka);
                    })
                    .toArray(String[]::new);

            SSLPossession pos = X509Authentication
                    .createPossession(hc, supportedKeyTypes);
            if (pos == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning("No available authentication scheme");
                }
            }
            return pos;
        }
    }
}
