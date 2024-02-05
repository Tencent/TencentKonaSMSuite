/*
 * Copyright (c) 2015, 2022, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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

package com.tencent.kona.sun.security.ssl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.ProviderException;
import java.text.MessageFormat;
import java.util.Locale;

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.sun.security.internal.spec.TlsPrfParameterSpec;
import com.tencent.kona.sun.security.ssl.CipherSuite.HashAlg;
import com.tencent.kona.sun.security.ssl.SSLHandshake.HandshakeMessage;
import com.tencent.kona.sun.security.util.HexDumpEncoder;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static com.tencent.kona.sun.security.ssl.CipherSuite.HashAlg.H_SM3;

final class TLCPFinished {

    static final SSLConsumer tlcpHandshakeConsumer
            = new TLCPFinishedConsumer();
    static final HandshakeProducer tlcpHandshakeProducer
            = new TLCPFinishedProducer();

    private static final class FinishedMessage extends HandshakeMessage {
        private final byte[] verifyData;

        FinishedMessage(HandshakeContext context) throws IOException {
            super(context);

            VerifyDataScheme vds =
                    VerifyDataScheme.valueOf(context.negotiatedProtocol);

            byte[] vd;
            try {
                vd = vds.createVerifyData(context, false);
            } catch (IOException ioe) {
                throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                        "Failed to generate verify_data", ioe);
            }

            this.verifyData = vd;
        }

        FinishedMessage(HandshakeContext context,
                ByteBuffer m) throws IOException {
            super(context);
            int verifyDataLen = 12;
            if (context.negotiatedProtocol == ProtocolVersion.SSL30) {
                verifyDataLen = 36;
            } else if (context.negotiatedProtocol.useTLS13PlusSpec()) {
                verifyDataLen =
                        context.negotiatedCipherSuite.hashAlg.hashLength;
            }

            if (m.remaining() != verifyDataLen) {
                throw context.conContext.fatal(Alert.DECODE_ERROR,
                    "Inappropriate finished message: need " + verifyDataLen +
                    " but remaining " + m.remaining() + " bytes verify_data");
            }

            this.verifyData = new byte[verifyDataLen];
            m.get(verifyData);

            VerifyDataScheme vd =
                    VerifyDataScheme.valueOf(context.negotiatedProtocol);
            byte[] myVerifyData;
            try {
                myVerifyData = vd.createVerifyData(context, true);
            } catch (IOException ioe) {
                throw context.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                        "Failed to generate verify_data", ioe);
            }
            if (!MessageDigest.isEqual(myVerifyData, verifyData)) {
                throw context.conContext.fatal(Alert.DECRYPT_ERROR,
                        "The Finished message cannot be verified.");
            }
        }

        @Override
        public SSLHandshake handshakeType() {
            return SSLHandshake.FINISHED;
        }

        @Override
        public int messageLength() {
            return verifyData.length;
        }

        @Override
        public void send(HandshakeOutStream hos) throws IOException {
            hos.write(verifyData);
        }

        @Override
        public String toString() {
            MessageFormat messageFormat = new MessageFormat(
                    "\"Finished\": '{'\n" +
                    "  \"verify data\": '{'\n" +
                    "{0}\n" +
                    "  '}'\n" +
                    "'}'",
                    Locale.ENGLISH);

            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            Object[] messageFields = {
                    Utilities.indent(hexEncoder.encode(verifyData), "    "),
                };
            return messageFormat.format(messageFields);
        }
    }

    interface VerifyDataGenerator {
        byte[] createVerifyData(HandshakeContext context,
                boolean isValidation) throws IOException;
    }

    enum VerifyDataScheme {
        TLCP11("kdf_tlcp11",  new TLCP11VerifyDataGenerator());

        final String name;
        final VerifyDataGenerator generator;

        VerifyDataScheme(String name, VerifyDataGenerator verifyDataGenerator) {
            this.name = name;
            this.generator = verifyDataGenerator;
        }

        static VerifyDataScheme valueOf(ProtocolVersion protocolVersion) {
            switch (protocolVersion) {
                case TLCP11:
                    return VerifyDataScheme.TLCP11;
                default:
                    return null;
            }
        }

        public byte[] createVerifyData(HandshakeContext context,
                boolean isValidation) throws IOException {
            if (generator != null) {
                return generator.createVerifyData(context, isValidation);
            }

            throw new UnsupportedOperationException("Not supported yet.");
        }
    }

    private static final class TLCP11VerifyDataGenerator
            implements VerifyDataGenerator {

        @Override
        public byte[] createVerifyData(HandshakeContext context,
                                       boolean isValidation) throws IOException {
            HandshakeHash handshakeHash = context.handshakeHash;
            SecretKey masterSecretKey =
                    context.handshakeSession.getMasterSecret();

            boolean useClientLabel =
                    (context.sslConfig.isClientMode && !isValidation) ||
                            (!context.sslConfig.isClientMode && isValidation);
            String tlcpLabel;
            if (useClientLabel) {
                tlcpLabel = "client finished";
            } else {
                tlcpLabel = "server finished";
            }

            try {
                byte[] seed = handshakeHash.digest();
                String prfAlg = "TlcpPrf";
                HashAlg hashAlg = H_SM3;

                /*
                 * RFC 5246/7.4.9 says that finished messages can
                 * be ciphersuite-specific in both length/PRF hash
                 * algorithm.  If we ever run across a different
                 * length, this call will need to be updated.
                 */
                @SuppressWarnings("deprecation")
                TlsPrfParameterSpec spec = new TlsPrfParameterSpec(
                        masterSecretKey, tlcpLabel, seed, 12,
                        hashAlg.name, hashAlg.hashLength, hashAlg.blockSize);
                KeyGenerator kg = CryptoInsts.getKeyGenerator(prfAlg);
                kg.init(spec);
                SecretKey prfKey = kg.generateKey();
                if (!"RAW".equals(prfKey.getFormat())) {
                    throw new ProviderException(
                            "Invalid PRF output, format must be RAW. " +
                                    "Format received: " + prfKey.getFormat());
                }
                return prfKey.getEncoded();
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("PRF failed", e);
            }
        }
    }

    static final class TLCPFinishedConsumer implements SSLConsumer {

        private TLCPFinishedConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                            ByteBuffer message) throws IOException {
            // The consuming happens in handshake context only.
            HandshakeContext hc = (HandshakeContext)context;

            // This consumer can be used only once.
            hc.handshakeConsumers.remove(SSLHandshake.FINISHED.id);

            // We should not be processing finished messages unless
            // we have received ChangeCipherSpec
            if (hc.conContext.consumers.containsKey(
                    ContentType.CHANGE_CIPHER_SPEC.id)) {
                throw hc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                        "Missing ChangeCipherSpec message");
            }

            if (hc.sslConfig.isClientMode) {
                onConsumeFinished((ClientHandshakeContext)context, message);
            } else {
                onConsumeFinished((ServerHandshakeContext)context, message);
            }
        }

        private void onConsumeFinished(ClientHandshakeContext chc,
                                       ByteBuffer message) throws IOException {
            FinishedMessage fm = new FinishedMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                        "Consuming server Finished handshake message", fm);
            }

            if (chc.conContext.secureRenegotiation) {
                chc.conContext.serverVerifyData = fm.verifyData;
            }

            if (!chc.isResumption) {
                if (chc.handshakeSession.isRejoinable()) {
                    ((SSLSessionContextImpl)chc.sslContext.
                            engineGetClientSessionContext()).put(
                            chc.handshakeSession);
                }
                chc.conContext.conSession = chc.handshakeSession.finish();
                chc.conContext.protocolVersion = chc.negotiatedProtocol;

                // handshake context cleanup.
                chc.handshakeFinished = true;
//                recordEvent(chc.conContext.conSession);

                // May need to retransmit the last flight for DTLS.
                if (!chc.sslContext.isDTLS()) {
                    chc.conContext.finishHandshake();
                }
            } else {
                chc.handshakeProducers.put(SSLHandshake.FINISHED.id,
                        SSLHandshake.FINISHED);
            }

            //
            // produce
            //
            SSLHandshake[] probableHandshakeMessages = new SSLHandshake[] {
                    SSLHandshake.FINISHED
            };

            for (SSLHandshake hs : probableHandshakeMessages) {
                HandshakeProducer handshakeProducer =
                        chc.handshakeProducers.remove(hs.id);
                if (handshakeProducer != null) {
                    handshakeProducer.produce(chc, fm);
                }
            }
        }

        private void onConsumeFinished(ServerHandshakeContext shc,
                                       ByteBuffer message) throws IOException {
            // Make sure that any expected CertificateVerify message
            // has been received and processed.
            if (!shc.isResumption) {
                if (shc.handshakeConsumers.containsKey(
                        SSLHandshake.CERTIFICATE_VERIFY.id)) {
                    throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                            "Unexpected Finished handshake message");
                }
            }

            FinishedMessage fm = new FinishedMessage(shc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                        "Consuming client Finished handshake message", fm);
            }

            if (shc.conContext.secureRenegotiation) {
                shc.conContext.clientVerifyData = fm.verifyData;
            }

            if (shc.isResumption) {
                if (shc.handshakeSession.isRejoinable() &&
                        !shc.statelessResumption) {
                    ((SSLSessionContextImpl)shc.sslContext.
                            engineGetServerSessionContext()).put(
                            shc.handshakeSession);
                }
                shc.conContext.conSession = shc.handshakeSession.finish();
                shc.conContext.protocolVersion = shc.negotiatedProtocol;

                // handshake context cleanup.
                shc.handshakeFinished = true;
//                recordEvent(shc.conContext.conSession);

                // May need to retransmit the last flight for DTLS.
                if (!shc.sslContext.isDTLS()) {
                    shc.conContext.finishHandshake();
                }
            } else {
                shc.handshakeProducers.put(SSLHandshake.FINISHED.id,
                        SSLHandshake.FINISHED);
            }

            //
            // produce
            //
            SSLHandshake[] probableHandshakeMessages = new SSLHandshake[] {
                    SSLHandshake.FINISHED
            };

            for (SSLHandshake hs : probableHandshakeMessages) {
                HandshakeProducer handshakeProducer =
                        shc.handshakeProducers.remove(hs.id);
                if (handshakeProducer != null) {
                    handshakeProducer.produce(shc, fm);
                }
            }
        }
    }

    static final class TLCPFinishedProducer implements HandshakeProducer {

        private TLCPFinishedProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                              HandshakeMessage message) throws IOException {
            // The consuming happens in handshake context only.
            HandshakeContext hc = (HandshakeContext)context;
            if (hc.sslConfig.isClientMode) {
                return onProduceFinished(
                        (ClientHandshakeContext)context, message);
            } else {
                return onProduceFinished(
                        (ServerHandshakeContext)context, message);
            }
        }

        private byte[] onProduceFinished(ClientHandshakeContext chc,
                HandshakeMessage message) throws IOException {
            // Refresh handshake hash
            chc.handshakeHash.update();

            FinishedMessage fm = new FinishedMessage(chc);

            // Change write cipher and delivery ChangeCipherSpec message.
            ChangeCipherSpec.t10Producer.produce(chc, message);

            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                        "Produced client Finished handshake message", fm);
            }

            // Output the handshake message.
            fm.write(chc.handshakeOutput);
            chc.handshakeOutput.flush();

            /*
             * save server verify data for secure renegotiation
             */
            if (chc.conContext.secureRenegotiation) {
                chc.conContext.clientVerifyData = fm.verifyData;
            }

            if (chc.statelessResumption) {
                chc.handshakeConsumers.put(
                        SSLHandshake.NEW_SESSION_TICKET.id, SSLHandshake.NEW_SESSION_TICKET);
            }
            // update the consumers and producers
            if (!chc.isResumption) {
                chc.conContext.consumers.put(ContentType.CHANGE_CIPHER_SPEC.id,
                        ChangeCipherSpec.t10Consumer);
                chc.handshakeConsumers.put(
                        SSLHandshake.FINISHED.id, SSLHandshake.FINISHED);
                chc.conContext.inputRecord.expectingFinishFlight();
            } else {
                if (chc.handshakeSession.isRejoinable()) {
                    ((SSLSessionContextImpl)chc.sslContext.
                            engineGetClientSessionContext()).put(
                            chc.handshakeSession);
                }
                chc.conContext.conSession = chc.handshakeSession.finish();
                chc.conContext.protocolVersion = chc.negotiatedProtocol;

                // handshake context cleanup.
                chc.handshakeFinished = true;

                // May need to retransmit the last flight for DTLS.
                if (!chc.sslContext.isDTLS()) {
                    chc.conContext.finishHandshake();
                }
            }

            // The handshake message has been delivered.
            return null;
        }

        private byte[] onProduceFinished(ServerHandshakeContext shc,
                HandshakeMessage message) throws IOException {
            if (shc.statelessResumption) {
                NewSessionTicket.handshake12Producer.produce(shc, message);
            }

            // Refresh handshake hash
            shc.handshakeHash.update();

            FinishedMessage fm = new FinishedMessage(shc);

            // Change write cipher and delivery ChangeCipherSpec message.
            ChangeCipherSpec.t10Producer.produce(shc, message);

            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                        "Produced server Finished handshake message", fm);
            }

            // Output the handshake message.
            fm.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();

            /*
             * save client verify data for secure renegotiation
             */
            if (shc.conContext.secureRenegotiation) {
                shc.conContext.serverVerifyData = fm.verifyData;
            }

            // update the consumers and producers
            if (shc.isResumption) {
                shc.conContext.consumers.put(ContentType.CHANGE_CIPHER_SPEC.id,
                        ChangeCipherSpec.t10Consumer);
                shc.handshakeConsumers.put(
                        SSLHandshake.FINISHED.id, SSLHandshake.FINISHED);
                shc.conContext.inputRecord.expectingFinishFlight();
            } else {
                // Set the session's context based on stateless/cache status
                if (shc.statelessResumption &&
                        shc.handshakeSession.isStatelessable()) {
                    shc.handshakeSession.setContext((SSLSessionContextImpl)
                            shc.sslContext.engineGetServerSessionContext());
                } else {
                    if (shc.handshakeSession.isRejoinable()) {
                        ((SSLSessionContextImpl)shc.sslContext.
                                engineGetServerSessionContext()).put(
                                shc.handshakeSession);
                    }
                }
                shc.conContext.conSession = shc.handshakeSession.finish();
                shc.conContext.protocolVersion = shc.negotiatedProtocol;

                // handshake context cleanup.
                shc.handshakeFinished = true;

                // May need to retransmit the last flight for DTLS.
                if (!shc.sslContext.isDTLS()) {
                    shc.conContext.finishHandshake();
                }
            }

            // The handshake message has been delivered.
            return null;
        }
    }
}
