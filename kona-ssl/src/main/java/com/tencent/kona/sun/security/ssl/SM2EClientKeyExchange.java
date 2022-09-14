package com.tencent.kona.sun.security.ssl;

import com.tencent.kona.crypto.provider.SM2PublicKey;
import com.tencent.kona.crypto.spec.SM2KeyAgreementParamSpec;
import com.tencent.kona.crypto.util.Constants;
import com.tencent.kona.sun.security.ssl.SM2EKeyExchange.SM2ECredentials;
import com.tencent.kona.sun.security.ssl.SM2EKeyExchange.SM2EPossession;
import com.tencent.kona.sun.security.ssl.SSLHandshake.HandshakeMessage;
import com.tencent.kona.sun.security.ssl.TLCPAuthentication.TLCPCredentials;
import com.tencent.kona.sun.security.ssl.TLCPAuthentication.TLCPPossession;
import com.tencent.kona.sun.security.util.HexDumpEncoder;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.MessageFormat;
import java.util.Locale;

/**
 * Pack of the ephemeral SM2 ClientKeyExchange handshake message.
 */
public class SM2EClientKeyExchange {

    static final SSLConsumer sm2eHandshakeConsumer
            = new SM2EClientKeyExchangeConsumer();
    static final HandshakeProducer sm2eHandshakeProducer
            = new SM2EClientKeyExchangeProducer();

    private static final class SM2EClientKeyExchangeMessage
            extends HandshakeMessage {
        private static final byte CURVE_NAMED_CURVE = (byte)0x03;
        private final byte[] encodedPoint;

        SM2EClientKeyExchangeMessage(HandshakeContext handshakeContext,
                                     byte[] encodedPublicKey) {
            super(handshakeContext);

            this.encodedPoint = encodedPublicKey;
        }

        SM2EClientKeyExchangeMessage(HandshakeContext handshakeContext,
                                     ByteBuffer m) throws IOException {
            super(handshakeContext);

            Record.getInt8(m);
            Record.getInt16(m);

            if (m.remaining() != 0) {       // explicit PublicValueEncoding
                this.encodedPoint = Record.getBytes8(m);
            } else {
                this.encodedPoint = new byte[0];
            }
        }

        @Override
        public SSLHandshake handshakeType() {
            return SSLHandshake.CLIENT_KEY_EXCHANGE;
        }

        @Override
        public int messageLength() {
            if (encodedPoint == null || encodedPoint.length == 0) {
                return 0;
            } else {
                return 1 + encodedPoint.length + 3;
            }
        }

        @Override
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putInt8(CURVE_NAMED_CURVE);
            hos.putInt16(NamedGroup.CURVESM2.id);

            if (encodedPoint != null && encodedPoint.length != 0) {
                hos.putBytes8(encodedPoint);
            }
        }

        @Override
        public String toString() {
            MessageFormat messageFormat = new MessageFormat(
                "\"SM2 ClientKeyExchange\": '{'\n" +
                "  \"SM2 public\": '{'\n" +
                "{0}\n" +
                "  '}',\n" +
                "'}'",
                Locale.ENGLISH);
            if (encodedPoint == null || encodedPoint.length == 0) {
                Object[] messageFields = {
                    "    <implicit>"
                };
                return messageFormat.format(messageFields);
            } else {
                HexDumpEncoder hexEncoder = new HexDumpEncoder();
                Object[] messageFields = {
                    Utilities.indent(
                            hexEncoder.encodeBuffer(encodedPoint), "    "),
                };
                return messageFormat.format(messageFields);
            }
        }
    }

    private static final class SM2EClientKeyExchangeProducer
            implements HandshakeProducer {

        // Prevent instantiation of this class.
        private SM2EClientKeyExchangeProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The producing happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            SM2ECredentials sm2eCredentials = null;
            for (SSLCredentials cd : chc.handshakeCredentials) {
                if (cd instanceof SM2EKeyExchange.SM2ECredentials) {
                    sm2eCredentials = (SM2ECredentials) cd;
                    break;
                }
            }

            if (sm2eCredentials == null) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR,
                    "No SM2E credentials negotiated for client key exchange");
            }

            TLCPPossession tlcpPossession = null;
            for (SSLPossession possession : chc.handshakePossessions) {
                if (possession instanceof TLCPPossession) {
                    tlcpPossession = (TLCPPossession) possession;
                    break;
                }
            }
            SM2EPossession sm2ePossession = new SM2EPossession(
                    tlcpPossession, sm2eCredentials.namedGroup,
                    chc.sslContext.getSecureRandom());

            chc.handshakePossessions.add(sm2ePossession);

            // Write the EC/XEC message.
            SM2EClientKeyExchangeMessage cke =
                    new SM2EClientKeyExchangeMessage(
                            chc, sm2ePossession.encode());

            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                    "Produced SM2E ClientKeyExchange handshake message", cke);
            }

            // Output the handshake message.
            cke.write(chc.handshakeOutput);
            chc.handshakeOutput.flush();

            TLCPCredentials tlcpCredentials = null;
            for (SSLCredentials sslCredentials : chc.handshakeCredentials) {
                if (sslCredentials instanceof TLCPCredentials) {
                    tlcpCredentials = (TLCPCredentials)sslCredentials;
                    break;
                }
            }

            // update the states
            SSLKeyExchange ke = SSLKeyExchange.valueOf(
                    chc.negotiatedCipherSuite.keyExchange,
                    chc.negotiatedProtocol);
            if (ke == null) {
                // unlikely
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR,
                        "Not supported key exchange type");
            } else {
                SM2KeyAgreementParamSpec params = new SM2KeyAgreementParamSpec(
                        Constants.defaultId(),
                        (ECPrivateKey) tlcpPossession.popEncPrivateKey,
                        (ECPublicKey) tlcpPossession.popEncPublicKey,
                        Constants.defaultId(),
                        (ECPublicKey) tlcpCredentials.popEncPublicKey,
                        false,
                        48);
                SSLKeyDerivation masterKD = ke.createKeyDerivation(chc);
                SecretKey masterSecret =
                        masterKD.deriveKey("MasterSecret", params);
                chc.handshakeSession.setMasterSecret(masterSecret);

                SSLTrafficKeyDerivation kd =
                        SSLTrafficKeyDerivation.valueOf(chc.negotiatedProtocol);
                if (kd == null) {
                    // unlikely
                    throw chc.conContext.fatal(Alert.INTERNAL_ERROR,
                            "Not supported key derivation: " +
                            chc.negotiatedProtocol);
                } else {
                    chc.handshakeKeyDerivation =
                        kd.createKeyDerivation(chc, masterSecret);
                }
            }

            // The handshake message has been delivered.
            return null;
        }
    }

    private static final class SM2EClientKeyExchangeConsumer
            implements SSLConsumer {

        // Prevent instantiation of this class.
        private SM2EClientKeyExchangeConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                ByteBuffer message) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            // Find a good EC/XEC credential to use, determine the
            // NamedGroup to use for creating Possessions/Credentials/Keys.
            SM2EPossession sm2ePossession = null;
            for (SSLPossession possession : shc.handshakePossessions) {
                if (possession instanceof SM2EPossession) {
                    sm2ePossession = (SM2EPossession)possession;
                    break;
                }
            }

            if (sm2ePossession == null) {
                // unlikely
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                    "No expected SM2E possessions for client key exchange");
            }

            NamedGroup namedGroup = NamedGroup.valueOf(
                    sm2ePossession.popEncPublicKey.getParams());
            if (namedGroup != NamedGroup.CURVESM2) {
                // unlikely, have been checked during cipher suite negotiation
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Unsupported EC server cert for SM2E client key exchange");
            }

            SSLKeyExchange ke = SSLKeyExchange.valueOf(
                    shc.negotiatedCipherSuite.keyExchange,
                    shc.negotiatedProtocol);
            if (ke == null) {
                // unlikely
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                        "Not supported key exchange type");
            }

            // parse the EC/XEC handshake message
            SM2EClientKeyExchangeMessage cke =
                    new SM2EClientKeyExchangeMessage(shc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                    "Consuming SM2E ClientKeyExchange handshake message", cke);
            }

            // create the credentials
            shc.handshakeCredentials.add(new SM2ECredentials(
                    new SM2PublicKey(cke.encodedPoint), namedGroup));

            TLCPCredentials tlcpCredentials = null;
            for (SSLCredentials sslCredentials : shc.handshakeCredentials) {
                if (sslCredentials instanceof TLCPCredentials) {
                    tlcpCredentials = (TLCPCredentials)sslCredentials;
                    break;
                }
            }

            // update the states
            SM2KeyAgreementParamSpec params = new SM2KeyAgreementParamSpec(
                    Constants.defaultId(),
                    sm2ePossession.popEncPrivateKey,
                    sm2ePossession.popEncPublicKey,
                    Constants.defaultId(),
                    (ECPublicKey) tlcpCredentials.popEncPublicKey,
                    true,
                    48);
            SSLKeyDerivation masterKD = ke.createKeyDerivation(shc);
            SecretKey masterSecret =
                    masterKD.deriveKey("MasterSecret", params);
            shc.handshakeSession.setMasterSecret(masterSecret);

            SSLTrafficKeyDerivation kd =
                    SSLTrafficKeyDerivation.valueOf(shc.negotiatedProtocol);
            if (kd == null) {
                // unlikely
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                    "Not supported key derivation: " + shc.negotiatedProtocol);
            } else {
                shc.handshakeKeyDerivation =
                    kd.createKeyDerivation(shc, masterSecret);
            }
        }
    }
}
