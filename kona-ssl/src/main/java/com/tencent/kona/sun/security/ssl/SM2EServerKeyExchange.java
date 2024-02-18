/*
 * Copyright (c) 2022, 2023, Oracle and/or its affiliates. All rights reserved.
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
import java.security.CryptoPrimitive;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.text.MessageFormat;
import java.util.EnumSet;
import java.util.Locale;

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.crypto.spec.SM2PublicKeySpec;
import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;
import com.tencent.kona.crypto.CryptoUtils;
import com.tencent.kona.sun.security.ssl.TLCPAuthentication.TLCPCredentials;
import com.tencent.kona.sun.security.ssl.TLCPAuthentication.TLCPPossession;
import com.tencent.kona.sun.security.ssl.SSLHandshake.HandshakeMessage;
import com.tencent.kona.sun.security.util.HexDumpEncoder;

/**
 * Pack of the ephemeral SM2 ServerKeyExchange handshake message.
 */
public class SM2EServerKeyExchange {

    static final SSLConsumer sm2eHandshakeConsumer
            = new SM2EServerKeyExchangeConsumer();
    static final HandshakeProducer sm2eHandshakeProducer
            = new SM2EServerKeyExchangeProducer();

    private static final class SM2EServerKeyExchangeMessage
            extends HandshakeMessage {

        private static final byte CURVE_NAMED_CURVE = (byte)0x03;

        // id of the named curve
        private final NamedGroup namedGroup;

        // encoded public point
        private final byte[] publicPoint;

        // signature bytes, or null if anonymous
        private final byte[] paramsSignature;

        // the parsed credential object
        private SSLCredentials sslCredentials;

        SM2EServerKeyExchangeMessage(
                HandshakeContext handshakeContext) throws IOException {
            super(handshakeContext);

            // This happens in server side only.
            ServerHandshakeContext shc =
                    (ServerHandshakeContext)handshakeContext;

            SM2EKeyExchange.SM2EPossession sm2ePossession = null;
            TLCPPossession tlcpPossession = null;
            for (SSLPossession possession : shc.handshakePossessions) {
                if (possession instanceof SM2EKeyExchange.SM2EPossession) {
                    sm2ePossession = (SM2EKeyExchange.SM2EPossession) possession;
                    if (tlcpPossession != null) {
                        break;
                    }
                } else if (possession instanceof TLCPPossession) {
                    tlcpPossession = (TLCPPossession) possession;
                    if (sm2ePossession != null) {
                        break;
                    }
                }
            }

            if (sm2ePossession == null) {
                // unlikely
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "No SM2 credentials negotiated for server key exchange");
            }

            // Find the NamedGroup used for the ephemeral keys.
            ECParameterSpec params = sm2ePossession.popEncPublicKey.getParams();
            namedGroup = params != null ? NamedGroup.valueOf(params) : null;
            if ((namedGroup == null) || (!namedGroup.isAvailable)
                    || namedGroup != NamedGroup.CURVESM2) {
                // unlikely
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Missing or improper named group: " + namedGroup);
            }

            ECPoint ecPoint = sm2ePossession.popEncPublicKey.getW();
            if (ecPoint == null) {
                // unlikely
                throw shc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Missing public point for named group: " + namedGroup);
            }

            publicPoint = CryptoUtils.pubKey(sm2ePossession.ephemeralPublicKey.getW());

            Signature signer;
            try {
                signer = CryptoInsts.getSignature(
                        SignatureScheme.SM2SIG_SM3.algorithm);

                signer.setParameter(new SM2SignatureParameterSpec(
                        (ECPublicKey) tlcpPossession.popSignPublicKey));

                signer.initSign(tlcpPossession.popSignPrivateKey);
            } catch (NoSuchAlgorithmException | InvalidKeyException |
                    InvalidAlgorithmParameterException e) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                    "Unsupported signature algorithm: " +
                    sm2ePossession.popEncPrivateKey.getAlgorithm(), e);
            }

            byte[] signature;
            try {
                updateSignature(signer,
                        shc.clientHelloRandom.randomBytes,
                        shc.serverHelloRandom.randomBytes,
                        namedGroup.id,
                        publicPoint);
                signature = signer.sign();
            } catch (SignatureException ex) {
                throw shc.conContext.fatal(Alert.INTERNAL_ERROR,
                    "Failed to sign ecdhe parameters: " +
                    sm2ePossession.popEncPrivateKey.getAlgorithm(), ex);
            }
            paramsSignature = signature;
        }

        SM2EServerKeyExchangeMessage(HandshakeContext handshakeContext,
                                     ByteBuffer m) throws IOException {
            super(handshakeContext);

            // This happens in client side only.
            ClientHandshakeContext chc =
                    (ClientHandshakeContext)handshakeContext;

            byte curveType = (byte)Record.getInt8(m);
            if (curveType != CURVE_NAMED_CURVE) {
                // Unlikely as only the named curves should be negotiated.
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Unsupported ECCurveType: " + curveType);
            }

            int namedGroupId = Record.getInt16(m);
            this.namedGroup = NamedGroup.valueOf(namedGroupId);
            if (namedGroup == null) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Unknown named group ID: " + namedGroupId);
            }

            if (!NamedGroup.isEnabled(chc.sslConfig, namedGroup)) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Unsupported named group: " + namedGroup);
            }

            publicPoint = Record.getBytes8(m);
            if (publicPoint.length == 0) {
                throw chc.conContext.fatal(Alert.ILLEGAL_PARAMETER,
                    "Insufficient Point data: " + namedGroup);
            }

            try {
                KeyFactory keyFactory = KeyFactory.getInstance("SM2");
                ECPublicKey ecPublicKey = (ECPublicKey) keyFactory.generatePublic(
                        new SM2PublicKeySpec(publicPoint));
                sslCredentials = new SM2EKeyExchange.SM2ECredentials(
                        ecPublicKey, namedGroup);
                if (handshakeContext.algorithmConstraints != null &&
                        sslCredentials instanceof NamedGroupCredentials) {
                    NamedGroupCredentials namedGroupCredentials
                            = (NamedGroupCredentials) sslCredentials;
                    if (!handshakeContext.algorithmConstraints.permits(
                            EnumSet.of(CryptoPrimitive.KEY_AGREEMENT),
                            namedGroupCredentials.getPublicKey())) {
                        chc.conContext.fatal(Alert.INSUFFICIENT_SECURITY,
                            "ServerKeyExchange for " + namedGroup +
                            " does not comply with algorithm constraints");
                    }
                }
            } catch (GeneralSecurityException ex) {
                throw chc.conContext.fatal(Alert.UNEXPECTED_MESSAGE,
                        "Cannot decode named group: " +
                        NamedGroup.nameOf(namedGroupId));
            }

            TLCPCredentials tlcpCredentials = null;
            for (SSLCredentials cd : chc.handshakeCredentials) {
                if (cd instanceof TLCPCredentials) {
                    tlcpCredentials = (TLCPCredentials)cd;
                    break;
                }
            }

            if (tlcpCredentials == null) {
                // anonymous, no authentication, no signature
                if (m.hasRemaining()) {
                    throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                        "Invalid DH ServerKeyExchange: unknown extra data");
                }
                this.paramsSignature = null;

                return;
            }

            // read and verify the signature
            paramsSignature = Record.getBytes16(m);
            Signature signer;
            try {
                signer = CryptoInsts.getSignature(
                        SignatureScheme.SM2SIG_SM3.algorithm);

                signer.setParameter(new SM2SignatureParameterSpec(
                        (ECPublicKey) tlcpCredentials.popSignPublicKey));

                signer.initVerify(tlcpCredentials.popSignPublicKey);
            } catch (NoSuchAlgorithmException | InvalidKeyException
                    | InvalidAlgorithmParameterException e) {
                throw chc.conContext.fatal(Alert.INTERNAL_ERROR,
                    "Unsupported signature algorithm: " +
                    tlcpCredentials.popSignPublicKey.getAlgorithm(), e);
            }

            try {
                updateSignature(signer,
                        chc.clientHelloRandom.randomBytes,
                        chc.serverHelloRandom.randomBytes,
                        namedGroup.id,
                        publicPoint);

                if (!signer.verify(paramsSignature)) {
                    throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                        "Invalid SM2 ServerKeyExchange signature");
                }
            } catch (SignatureException ex) {
                throw chc.conContext.fatal(Alert.HANDSHAKE_FAILURE,
                        "Cannot verify SM2 ServerKeyExchange signature", ex);
            }
        }

        @Override
        public SSLHandshake handshakeType() {
            return SSLHandshake.SERVER_KEY_EXCHANGE;
        }

        @Override
        public int messageLength() {
            int sigLen = 0;
            if (paramsSignature != null) {
                sigLen = 2 + paramsSignature.length;
            }

            return 4 + publicPoint.length + sigLen;
        }

        @Override
        public void send(HandshakeOutStream hos) throws IOException {
            hos.putInt8(CURVE_NAMED_CURVE);
            hos.putInt16(namedGroup.id);
            hos.putBytes8(publicPoint);
            if (paramsSignature != null) {
                hos.putBytes16(paramsSignature);
            }
        }

        @Override
        public String toString() {
            if (paramsSignature != null) {
                MessageFormat messageFormat = new MessageFormat(
                    "\"SM2 ServerKeyExchange\": '{'\n" +
                    "  \"parameters\":  '{'\n" +
                    "    \"named group\": \"{0}\"\n" +
                    "    \"ecdh public\": '{'\n" +
                    "{1}\n" +
                    "    '}',\n" +
                    "  '}',\n" +
                    "  \"signature\": '{'\n" +
                    "{2}\n" +
                    "  '}'\n" +
                    "'}'",
                    Locale.ENGLISH);

                HexDumpEncoder hexEncoder = new HexDumpEncoder();
                Object[] messageFields = {
                    namedGroup.name,
                    Utilities.indent(
                            hexEncoder.encodeBuffer(publicPoint), "      "),
                    Utilities.indent(
                            hexEncoder.encodeBuffer(paramsSignature), "    ")
                };

                return messageFormat.format(messageFields);
            } else {    // anonymous
                MessageFormat messageFormat = new MessageFormat(
                    "\"SM2 ServerKeyExchange\": '{'\n" +
                    "  \"parameters\":  '{'\n" +
                    "    \"named group\": \"{0}\"\n" +
                    "    \"ecdh public\": '{'\n" +
                    "{1}\n" +
                    "    '}',\n" +
                    "  '}'\n" +
                    "'}'",
                    Locale.ENGLISH);

                HexDumpEncoder hexEncoder = new HexDumpEncoder();
                Object[] messageFields = {
                    namedGroup.name,
                    Utilities.indent(
                            hexEncoder.encodeBuffer(publicPoint), "      "),
                };

                return messageFormat.format(messageFields);
            }
        }

        private static void updateSignature(Signature sig,
                byte[] clntNonce, byte[] svrNonce, int namedGroupId,
                byte[] publicPoint) throws SignatureException {
            sig.update(clntNonce);
            sig.update(svrNonce);

            sig.update(CURVE_NAMED_CURVE);
            sig.update((byte)((namedGroupId >> 8) & 0xFF));
            sig.update((byte)(namedGroupId & 0xFF));
            sig.update((byte)publicPoint.length);
            sig.update(publicPoint);
        }
    }

    private static final class SM2EServerKeyExchangeProducer
            implements HandshakeProducer {

        // Prevent instantiation of this class.
        private SM2EServerKeyExchangeProducer() {
            // blank
        }

        @Override
        public byte[] produce(ConnectionContext context,
                HandshakeMessage message) throws IOException {
            // The producing happens in server side only.
            ServerHandshakeContext shc = (ServerHandshakeContext)context;
            SM2EServerKeyExchangeMessage skem =
                    new SM2EServerKeyExchangeMessage(shc);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                    "Produced SM2 ServerKeyExchange handshake message", skem);
            }

            // Output the handshake message.
            skem.write(shc.handshakeOutput);
            shc.handshakeOutput.flush();

            // The handshake message has been delivered.
            return null;
        }
    }

    private static final class SM2EServerKeyExchangeConsumer
            implements SSLConsumer {

        // Prevent instantiation of this class.
        private SM2EServerKeyExchangeConsumer() {
            // blank
        }

        @Override
        public void consume(ConnectionContext context,
                ByteBuffer message) throws IOException {
            // The consuming happens in client side only.
            ClientHandshakeContext chc = (ClientHandshakeContext)context;

            // AlgorithmConstraints are checked during decoding
            SM2EServerKeyExchangeMessage skem =
                    new SM2EServerKeyExchangeMessage(chc, message);
            if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                SSLLogger.fine(
                    "Consuming SM2 ServerKeyExchange handshake message", skem);
            }

            //
            // update
            //
            chc.handshakeCredentials.add(skem.sslCredentials);

            //
            // produce
            //
            // Need no new handshake message producers here.
        }
    }
}
