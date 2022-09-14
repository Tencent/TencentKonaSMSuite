package com.tencent.kona.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.net.ssl.SSLException;
import com.tencent.kona.sun.security.ssl.SSLCipher.SSLReadCipher;
import com.tencent.kona.sun.security.ssl.SSLCipher.SSLWriteCipher;
import com.tencent.kona.sun.security.ssl.SSLHandshake.HandshakeMessage;
import com.tencent.kona.sun.security.ssl.SSLTrafficKeyDerivation.LegacyTrafficKeyDerivation;

final class TLCPChangeCipherSpec {

    static final SSLConsumer tlcpConsumer
            = new TLCPChangeCipherSpecConsumer();
    static final HandshakeProducer tlcpProducer
            = new TLCPChangeCipherSpecProducer();

    private static final class TLCPChangeCipherSpecProducer
            implements HandshakeProducer {

        // Prevent instantiation of this class.
        private TLCPChangeCipherSpecProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            HandshakeContext hc = (HandshakeContext)context;
            SSLKeyDerivation kd = hc.handshakeKeyDerivation;

            if (!(kd instanceof LegacyTrafficKeyDerivation)) {
                throw new UnsupportedOperationException("Not supported.");
            }
            LegacyTrafficKeyDerivation tkd = (LegacyTrafficKeyDerivation)kd;
            CipherSuite ncs = hc.negotiatedCipherSuite;
            Authenticator writeAuthenticator;
            if (ncs.bulkCipher.cipherType == CipherType.AEAD_CIPHER) {
                writeAuthenticator =
                        Authenticator.valueOf(hc.negotiatedProtocol);
            } else {
                try {
                    writeAuthenticator = Authenticator.valueOf(
                            hc.negotiatedProtocol, ncs.macAlg,
                            tkd.getTrafficKey(hc.sslConfig.isClientMode ?
                                    "clientMacKey" : "serverMacKey"));
                } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                    // unlikely
                    throw new SSLException("Algorithm missing: ", e);
                }
            }

            SecretKey writeKey =
                    tkd.getTrafficKey(hc.sslConfig.isClientMode ?
                                    "clientWriteKey" : "serverWriteKey");
            SecretKey writeIv =
                    tkd.getTrafficKey(hc.sslConfig.isClientMode ?
                                    "clientWriteIv" : "serverWriteIv");
            IvParameterSpec iv = (writeIv == null) ? null :
                    new IvParameterSpec(writeIv.getEncoded());
            SSLWriteCipher writeCipher;
            try {
                writeCipher = ncs.bulkCipher.createWriteCipher(
                        writeAuthenticator,
                        hc.negotiatedProtocol, writeKey, iv,
                        hc.sslContext.getSecureRandom());
            } catch (GeneralSecurityException gse) {
                // unlikely
                throw new SSLException("Algorithm missing: ", gse);
            }

            if (writeCipher == null) {
                throw hc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Illegal cipher suite (" + ncs +
                    ") and protocol version (" + hc.negotiatedProtocol + ")");
            }

            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Produced ChangeCipherSpec message");
            }

            hc.conContext.outputRecord.changeWriteCiphers(writeCipher, true);

            // The handshake message has been delivered.
            return null;
        }
    }

    private static final class TLCPChangeCipherSpecConsumer
            implements SSLConsumer {

        // Prevent instantiation of this class.
        private TLCPChangeCipherSpecConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                ByteBuffer message) throws IOException {
            TransportContext tc = (TransportContext)context;

            // This consumer can be used only once.
            tc.consumers.remove(ContentType.CHANGE_CIPHER_SPEC.id);

            // parse
            if (message.remaining() != 1 || message.get() != 1) {
                throw tc.fatal(Alert.UNEXPECTED_MESSAGE,
                        "Malformed or unexpected ChangeCipherSpec message");
            }
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine("Consuming ChangeCipherSpec message");
            }

            // validate
            if (tc.handshakeContext == null) {
                throw tc.fatal(Alert.HANDSHAKE_FAILURE,
                        "Unexpected ChangeCipherSpec message");
            }

            HandshakeContext hc = tc.handshakeContext;

            if (hc.handshakeKeyDerivation == null) {
                throw tc.fatal(Alert.UNEXPECTED_MESSAGE,
                        "Unexpected ChangeCipherSpec message");
            }

            SSLKeyDerivation kd = hc.handshakeKeyDerivation;
            if (kd instanceof LegacyTrafficKeyDerivation) {
                LegacyTrafficKeyDerivation tkd = (LegacyTrafficKeyDerivation)kd;
                CipherSuite ncs = hc.negotiatedCipherSuite;
                Authenticator readAuthenticator;
                if (ncs.bulkCipher.cipherType == CipherType.AEAD_CIPHER) {
                    readAuthenticator =
                            Authenticator.valueOf(hc.negotiatedProtocol);
                } else {
                    try {
                        readAuthenticator = Authenticator.valueOf(
                                hc.negotiatedProtocol, ncs.macAlg,
                                tkd.getTrafficKey(hc.sslConfig.isClientMode ?
                                        "serverMacKey" : "clientMacKey"));
                    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                        // unlikely
                        throw new SSLException("Algorithm missing: ", e);
                    }
                }

                SecretKey readKey =
                        tkd.getTrafficKey(hc.sslConfig.isClientMode ?
                                        "serverWriteKey" : "clientWriteKey");
                SecretKey readIv =
                        tkd.getTrafficKey(hc.sslConfig.isClientMode ?
                                        "serverWriteIv" : "clientWriteIv");
                IvParameterSpec iv = (readIv == null) ? null :
                        new IvParameterSpec(readIv.getEncoded());
                SSLReadCipher readCipher;
                try {
                    readCipher = ncs.bulkCipher.createReadCipher(
                            readAuthenticator,
                            hc.negotiatedProtocol, readKey, iv,
                            hc.sslContext.getSecureRandom());
                } catch (GeneralSecurityException gse) {
                    // unlikely
                    throw new SSLException("Algorithm missing: ", gse);
                }

                if (readCipher == null) {
                    throw hc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                        "Illegal cipher suite (" + hc.negotiatedCipherSuite +
                        ") and protocol version (" + hc.negotiatedProtocol +
                        ")");
                }

                tc.inputRecord.changeReadCiphers(readCipher);
            } else {
                throw new UnsupportedOperationException("Not supported.");
            }
        }
    }
}
