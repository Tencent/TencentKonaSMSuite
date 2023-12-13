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

import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;
import com.tencent.kona.pkix.PKIXUtils;
import com.tencent.kona.sun.security.util.HexDumpEncoder;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.text.MessageFormat;
import java.util.Locale;

import com.tencent.kona.sun.security.ssl.SSLHandshake.HandshakeMessage;
import com.tencent.kona.sun.security.ssl.TLCPAuthentication.TLCPCredentials;
import com.tencent.kona.sun.security.ssl.TLCPAuthentication.TLCPPossession;

final class TLCPCertificateVerify {

    static final SSLConsumer tlcpHandshakeConsumer
            = new TLCPCertificateVerifyConsumer();
    static final HandshakeProducer tlcpHandshakeProducer
            = new TLCPCertificateVerifyProducer();

    private static final class TLCPCertificateVerifyMessage
            extends HandshakeMessage {

        // the signature algorithm
        private final SignatureScheme signatureScheme;

        // signature bytes
        private final byte[] signature;

        TLCPCertificateVerifyMessage(HandshakeContext context,
                                     TLCPPossession tlcpPossession)
                throws IOException {
            super(context);

            // This happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext) context;

            signatureScheme = chc.negotiatedProtocol.isTLS12()
                    ? SignatureScheme.SM2SIG_SM3
                    : null;

            byte[] temporary;
            try {
                Signature signer = SignatureScheme.SM2SIG_SM3.getSigner(
                        tlcpPossession.popSignPrivateKey,
                        tlcpPossession.popSignPublicKey,
                        false);
                signer.update(chc.handshakeHash.digest());
                temporary = signer.sign();
            } catch (SignatureException se) {
                throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                        "Cannot produce CertificateVerify signature", se);
            }

            this.signature = temporary;
        }

        TLCPCertificateVerifyMessage(HandshakeContext handshakeContext,
                                     ByteBuffer m) throws IOException {
            super(handshakeContext);

            // This happens in server side only.
            ServerHandshakeContext shc =
                    (ServerHandshakeContext) handshakeContext;

            // struct {
            //     SignatureAndHashAlgorithm algorithm;
            //     opaque signature<0..2^16-1>;
            // } DigitallySigned;

            int minLen = shc.negotiatedProtocol.isTLS12() ? 4 : 2;
            if (m.remaining() < 4) {
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                        "Invalid CertificateVerify message: no sufficient data");
            }

            if (shc.negotiatedProtocol.isTLS12()) {
                // SignatureAndHashAlgorithm algorithm
                int ssid = Record.getInt16(m);
                this.signatureScheme = SignatureScheme.valueOf(ssid);
                if (signatureScheme == null) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "Invalid signature algorithm (" + ssid +
                                    ") used in CertificateVerify handshake message");
                }

                if (!shc.localSupportedSignAlgs.contains(signatureScheme)) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "Unsupported signature algorithm (" +
                                    signatureScheme.name +
                                    ") used in CertificateVerify handshake message");
                }
            } else {
                this.signatureScheme = null;
            }

            // read and verify the signature
            TLCPCredentials tlcpCredentials = null;
            for (SSLCredentials cd : shc.handshakeCredentials) {
                if (cd instanceof TLCPCredentials) {
                    tlcpCredentials = (TLCPCredentials) cd;
                    break;
                }
            }

            if (tlcpCredentials == null ||
                    tlcpCredentials.popSignPublicKey == null) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                        "No X509 credentials negotiated for CertificateVerify");
            }

            // opaque signature<0..2^16-1>;
            this.signature = Record.getBytes16(m);

            if (!(PKIXUtils.isSMCert(tlcpCredentials.popSignCert))) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                        "Only support SM certificate");
            }

            try {
                Signature signer = SignatureScheme.SM2SIG_SM3.getVerifier(
                        tlcpCredentials.popSignPublicKey);

                signer.update(shc.handshakeHash.digest());
                if (!signer.verify(signature)) {
                    throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                            "Invalid CertificateVerify signature");
                }
            } catch (NoSuchAlgorithmException |
                    InvalidAlgorithmParameterException nsae) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                        "Unsupported signature algorithm (" +
                                signatureScheme.name +
                                ") used in CertificateVerify handshake message", nsae);
            } catch (InvalidKeyException | SignatureException ikse) {
                throw shc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                        "Cannot verify CertificateVerify signature", ikse);
            }
        }

        @Override
        public SSLHandshake handshakeType() {
            return SSLHandshake.CERTIFICATE_VERIFY;
        }

        @Override
        public int messageLength() {
            if (signatureScheme != null) {
                //  2: signature algorithm
                // +2: length of signature
                return 4 + signature.length;
            }
            return 2 + signature.length;
        }

        @Override
        public void send(HandshakeOutStream hos) throws IOException {
            if (signatureScheme != null) {
                hos.putInt16(signatureScheme.id);
            }
            hos.putBytes16(signature);
        }

        @Override
        public String toString() {
            MessageFormat messageFormat = new MessageFormat(
                    "\"CertificateVerify\": '{'\n" +
                            "  \"signature algorithm\": {0}\n" +
                            "  \"signature\": '{'\n" +
                            "{1}\n" +
                            "  '}'\n" +
                            "'}'",
                    Locale.ENGLISH);

            HexDumpEncoder hexEncoder = new HexDumpEncoder();
            Object[] messageFields = {
                    signatureScheme != null ? signatureScheme.name : "",
                    Utilities.indent(
                            hexEncoder.encodeBuffer(signature), "    ")
            };

            return messageFormat.format(messageFields);
        }
    }

    private static final
            class TLCPCertificateVerifyProducer implements HandshakeProducer {
        // Prevent instantiation of this class.
        private TLCPCertificateVerifyProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The producing happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            TLCPPossession tlcpPossession = null;
            for (SSLPossession possession : chc.handshakePossessions) {
                if (possession instanceof TLCPPossession) {
                    tlcpPossession = (TLCPPossession)possession;
                    break;
                }
            }

            if (tlcpPossession == null ||
                    tlcpPossession.popSignPrivateKey == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.fine(
                        "No X.509 credentials negotiated for CertificateVerify");
                }

                return null;
            }

            TLCPCertificateVerifyMessage cvm =
                    new TLCPCertificateVerifyMessage(chc, tlcpPossession);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                        "Produced CertificateVerify handshake message", cvm);
            }

            // Output the handshake message.
            cvm.write(chc.handshakeOutput);
            chc.handshakeOutput.flush();

            // The handshake message has been delivered.
            return null;
        }
    }

    private static final class TLCPCertificateVerifyConsumer implements SSLConsumer {
        // Prevent instantiation of this class.
        private TLCPCertificateVerifyConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                ByteBuffer message) throws IOException {
            // The consuming happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;

            // Clean up this consumer
            shc.handshakeConsumers.remove(SSLHandshake.CERTIFICATE_VERIFY.id);

            // Ensure that the CV message follows the CKE
            if (shc.handshakeConsumers.containsKey(
                    SSLHandshake.CLIENT_KEY_EXCHANGE.id)) {
                throw shc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                        "Unexpected CertificateVerify handshake message");
            }

            TLCPCertificateVerifyMessage cvm =
                    new TLCPCertificateVerifyMessage(shc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                        "Consuming CertificateVerify handshake message", cvm);
            }

            //
            // update
            //
            // Need no additional validation.

            //
            // produce
            //
            // Need no new handshake message producers here.
        }
    }
}
