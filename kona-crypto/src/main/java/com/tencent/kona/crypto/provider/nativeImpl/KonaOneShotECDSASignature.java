/*
 * Copyright (c) 2009, 2021, Oracle and/or its affiliates. All rights reserved.
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

package com.tencent.kona.crypto.provider.nativeImpl;

import java.nio.ByteBuffer;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.crypto.util.Constants;
import com.tencent.kona.sun.security.ec.*;
import com.tencent.kona.sun.security.util.ArrayUtil;
import com.tencent.kona.sun.security.util.ECUtil;

/**
 * ECDSA signature implementation. This class currently supports the
 * following algorithm names:
 *
 *   . "NONEwithECDSA"
 *   . "SHA1withECDSA"
 *   . "SHA224withECDSA"
 *   . "SHA256withECDSA"
 *   . "SHA384withECDSA"
 *   . "SHA512withECDSA"
 *   . "SHA3-224withECDSA"
 *   . "SHA3-256withECDSA"
 *   . "SHA3-384withECDSA"
 *   . "SHA3-512withECDSA"
 *   . "NONEwithECDSAinP1363Format"
 *   . "SHA1withECDSAinP1363Format"
 *   . "SHA224withECDSAinP1363Format"
 *   . "SHA256withECDSAinP1363Format"
 *   . "SHA384withECDSAinP1363Format"
 *   . "SHA512withECDSAinP1363Format"
 *   . "SHA3-224withECDSAinP1363Format"
 *   . "SHA3-256withECDSAinP1363Format"
 *   . "SHA3-384withECDSAinP1363Format"
 *   . "SHA3-512withECDSAinP1363Format"
 *
 * @since   1.7
 */
abstract class KonaOneShotECDSASignature extends SignatureSpi {

    // message digest implementation we use
    private final int mdNID;
    private final ByteArrayWriter buffer = new ByteArrayWriter();

    // private key, if initialized for signing
    private ECPrivateKey privateKey;

    // public key, if initialized for verifying
    private ECPublicKey publicKey;

    // signature parameters
    private ECParameterSpec sigParams = null;

    // The format. true for the IEEE P1363 format. false (default) for ASN.1
    private final boolean p1363Format;

    /**
     * Constructs a new ECDSASignature.
     *
     * @exception ProviderException if the native ECC library is unavailable.
     */
    KonaOneShotECDSASignature() {
        this(false);
    }

    /**
     * Constructs a new ECDSASignature that will use the specified
     * signature format. {@code p1363Format} should be {@code true} to
     * use the IEEE P1363 format. If {@code p1363Format} is {@code false},
     * the DER-encoded ASN.1 format will be used. This constructor is
     * used by the RawECDSA subclasses.
     */
    KonaOneShotECDSASignature(boolean p1363Format) {
        this.mdNID = -1;
        this.p1363Format = p1363Format;
    }

    /**
     * Constructs a new ECDSASignature. Used by subclasses.
     */
    KonaOneShotECDSASignature(String digestName) {
        this(digestName, false);
    }

    /**
     * Constructs a new ECDSASignature that will use the specified
     * digest and signature format. {@code p1363Format} should be
     * {@code true} to use the IEEE P1363 format. If {@code p1363Format}
     * is {@code false}, the DER-encoded ASN.1 format will be used. This
     * constructor is used by subclasses.
     */
    KonaOneShotECDSASignature(String digestName, boolean p1363Format) {
        mdNID = Constants.getDigestNID(digestName);
        this.p1363Format = p1363Format;
    }

    // Class for Raw ECDSA signatures.
    static class RawECDSA extends KonaOneShotECDSASignature {

        // the longest supported digest is 512 bits (SHA-512)
        private static final int RAW_ECDSA_MAX = 64;

        private final byte[] precomputedDigest;
        private int offset = 0;

        RawECDSA(boolean p1363Format) {
            super(p1363Format);
            precomputedDigest = new byte[RAW_ECDSA_MAX];
        }

        // Stores the precomputed message digest value.
        @Override
        protected void engineUpdate(byte b) throws SignatureException {
            if (offset >= precomputedDigest.length) {
                offset = RAW_ECDSA_MAX + 1;
                return;
            }
            precomputedDigest[offset++] = b;
        }

        // Stores the precomputed message digest value.
        @Override
        protected void engineUpdate(byte[] b, int off, int len)
                throws SignatureException {
            if (offset >= precomputedDigest.length) {
                offset = RAW_ECDSA_MAX + 1;
                return;
            }
            System.arraycopy(b, off, precomputedDigest, offset, len);
            offset += len;
        }

        // Stores the precomputed message digest value.
        @Override
        protected void engineUpdate(ByteBuffer byteBuffer) {
            int len = byteBuffer.remaining();
            if (len <= 0) {
                return;
            }
            if (len >= precomputedDigest.length - offset) {
                offset = RAW_ECDSA_MAX + 1;
                return;
            }
            byteBuffer.get(precomputedDigest, offset, len);
            offset += len;
        }

        @Override
        protected void resetDigest() {
            offset = 0;
        }

        // Returns the precomputed message digest value.
        @Override
        protected byte[] getDigestValue() throws SignatureException {
            if (offset > RAW_ECDSA_MAX) {
                throw new SignatureException("Message digest is too long");

            }
            byte[] result = new byte[offset];
            System.arraycopy(precomputedDigest, 0, result, 0, offset);
            offset = 0;

            return result;
        }
    }

    // Nested class for NONEwithECDSA signatures
    public static final class Raw extends RawECDSA {
        public Raw() {
            super(false);
        }
    }

    // Nested class for NONEwithECDSAinP1363Format signatures
    public static final class RawinP1363Format extends RawECDSA {
        public RawinP1363Format() {
            super(true);
        }
    }

    // Nested class for SHA1withECDSA signatures
    public static final class SHA1 extends KonaOneShotECDSASignature {
        public SHA1() {
            super("SHA1");
        }
    }

    // Nested class for SHA1withECDSAinP1363Format signatures
    public static final class SHA1inP1363Format extends KonaOneShotECDSASignature {
        public SHA1inP1363Format() {
            super("SHA1", true);
        }
    }

    // Nested class for SHA224withECDSA signatures
    public static final class SHA224 extends KonaOneShotECDSASignature {
        public SHA224() {
            super("SHA-224");
        }
    }

    // Nested class for SHA224withECDSAinP1363Format signatures
    public static final class SHA224inP1363Format extends KonaOneShotECDSASignature {
        public SHA224inP1363Format() {
            super("SHA-224", true);
        }
    }

    // Nested class for SHA256withECDSA signatures
    public static final class SHA256 extends KonaOneShotECDSASignature {
        public SHA256() {
            super("SHA-256");
        }
    }

    // Nested class for SHA256withECDSAinP1363Format signatures
    public static final class SHA256inP1363Format extends KonaOneShotECDSASignature {
        public SHA256inP1363Format() {
            super("SHA-256", true);
        }
    }

    // Nested class for SHA384withECDSA signatures
    public static final class SHA384 extends KonaOneShotECDSASignature {
        public SHA384() {
            super("SHA-384");
        }
    }

    // Nested class for SHA384withECDSAinP1363Format signatures
    public static final class SHA384inP1363Format extends KonaOneShotECDSASignature {
        public SHA384inP1363Format() {
            super("SHA-384", true);
        }
    }

    // Nested class for SHA512withECDSA signatures
    public static final class SHA512 extends KonaOneShotECDSASignature {
        public SHA512() {
            super("SHA-512");
        }
    }

    // Nested class for SHA512withECDSAinP1363Format signatures
    public static final class SHA512inP1363Format extends KonaOneShotECDSASignature {
        public SHA512inP1363Format() {
            super("SHA-512", true);
        }
    }

    // Nested class for SHA3_224withECDSA signatures
    public static final class SHA3_224 extends KonaOneShotECDSASignature {
        public SHA3_224() {
            super("SHA3-224");
        }
    }

    // Nested class for SHA3_224withECDSAinP1363Format signatures
    public static final class SHA3_224inP1363Format extends KonaOneShotECDSASignature {
        public SHA3_224inP1363Format() {
            super("SHA3-224", true);
        }
    }

    // Nested class for SHA3_256withECDSA signatures
    public static final class SHA3_256 extends KonaOneShotECDSASignature {
        public SHA3_256() {
            super("SHA3-256");
        }
    }

    // Nested class for SHA3_256withECDSAinP1363Format signatures
    public static final class SHA3_256inP1363Format extends KonaOneShotECDSASignature {
        public SHA3_256inP1363Format() {
            super("SHA3-256", true);
        }
    }

    // Nested class for SHA3_384withECDSA signatures
    public static final class SHA3_384 extends KonaOneShotECDSASignature {
        public SHA3_384() {
            super("SHA3-384");
        }
    }

    // Nested class for SHA3_384withECDSAinP1363Format signatures
    public static final class SHA3_384inP1363Format extends KonaOneShotECDSASignature {
        public SHA3_384inP1363Format() {
            super("SHA3-384", true);
        }
    }

    // Nested class for SHA3_512withECDSA signatures
    public static final class SHA3_512 extends KonaOneShotECDSASignature {
        public SHA3_512() {
            super("SHA3-512");
        }
    }

    // Nested class for SHA3_512withECDSAinP1363Format signatures
    public static final class SHA3_512inP1363Format extends KonaOneShotECDSASignature {
        public SHA3_512inP1363Format() {
            super("SHA3-512", true);
        }
    }

    // initialize for verification. See JCA doc
    @Override
    protected void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException {
        ECPublicKey key = (ECPublicKey) ECKeyFactory.toECKey(publicKey);
        if (!isCompatible(this.sigParams, key.getParams())) {
            throw new InvalidKeyException("Key params does not match signature params");
        }

        // Should check that the supplied key is appropriate for signature
        // algorithm (e.g. P-256 for SHA256withECDSA)
        this.publicKey = key;
        this.privateKey = null;
        resetDigest();
    }

    // initialize for signing. See JCA doc
    @Override
    protected void engineInitSign(PrivateKey privateKey)
            throws InvalidKeyException {
        engineInitSign(privateKey, null);
    }

    // initialize for signing. See JCA doc
    @Override
    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
            throws InvalidKeyException {
        ECPrivateKey key = (ECPrivateKey) ECKeyFactory.toECKey(privateKey);
        if (!isCompatible(this.sigParams, key.getParams())) {
            throw new InvalidKeyException("Key params does not match signature params");
        }

        ECUtil.checkPrivateKey(key);
        // Should check that the supplied key is appropriate for signature
        // algorithm (e.g. P-256 for SHA256withECDSA)
        this.privateKey = key;
        this.publicKey = null;
        resetDigest();
    }

    /**
     * Resets the message digest if needed.
     */
    protected void resetDigest() {
        buffer.reset();
    }

    /**
     * Returns the message digest value.
     */
    protected byte[] getDigestValue() throws SignatureException {
        return buffer.toByteArray();
    }

    // update the signature with the plaintext data. See JCA doc
    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        buffer.write(b);
    }

    // update the signature with the plaintext data. See JCA doc
    @Override
    protected void engineUpdate(byte[] b, int off, int len)
            throws SignatureException {
        buffer.write(b, off, len);
    }

    // update the signature with the plaintext data. See JCA doc
    @Override
    protected void engineUpdate(ByteBuffer byteBuffer) {
        super.engineUpdate(byteBuffer);
    }

    private static boolean isCompatible(ECParameterSpec sigParams,
                                        ECParameterSpec keyParams) {
        if (sigParams == null) {
            // no restriction on key param
            return true;
        }
        return ECUtil.equals(sigParams, keyParams);
    }

    private byte[] signDigestImpl(ECPrivateKey priv) throws SignatureException {

        byte[] s = priv instanceof ECPrivateKeyImpl
                ? ((ECPrivateKeyImpl)priv).getArrayS()
                : ECUtil.sArray(priv.getS(), priv.getParams());
        ArrayUtil.reverse(s); // Little-endian to Big-endian

        ECParameterSpec curveParam = priv.getParams();
        int curveNID = Constants.getCurveNID(curveParam.toString());
        byte[] message = buffer.toByteArray();
        buffer.reset();
        byte[] sig = NativeCrypto.ecdsaOneShotSign(mdNID, curveNID, s, message);

        if (sig == null || sig.length == 0) {
            throw new SignatureException("Unable to produce signature");
        }

        return sig;
    }

    // sign the data and return the signature. See JCA doc
    @Override
    protected byte[] engineSign() throws SignatureException {
        byte[] sig = signDigestImpl(privateKey);

        if (p1363Format) {
            return ECUtil.decodeSignature(sig);
        } else {
            return sig;
        }
    }

    // verify the data and return the result. See JCA doc
    @Override
    protected boolean engineVerify(byte[] signature) throws SignatureException {

        ECPoint w = publicKey.getW();
        ECParameterSpec params = publicKey.getParams();

        // Partial public key validation
        try {
            ECUtil.validatePublicKey(w, params);
        } catch (InvalidKeyException e) {
            return false;
        }
        byte[] publicKey = ECUtil.encodePoint(w, params.getCurve());

        byte[] sig;
        if (!p1363Format) {
            sig = signature;
        } else {
            sig = ECUtil.decodeSignature(signature);
        }

        int curveNID = Constants.getCurveNID(params.toString());
        byte[] message = buffer.toByteArray();
        buffer.reset();
        return NativeCrypto.ecdsaOneShotVerify(mdNID, curveNID, publicKey, message, sig)
                == NativeCrypto.OPENSSL_SUCCESS;
    }

    // set parameter, not supported. See JCA doc
    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value)
            throws InvalidParameterException {
        throw new UnsupportedOperationException("setParameter() not supported");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (params != null && !(params instanceof ECParameterSpec)) {
            throw new InvalidAlgorithmParameterException("No parameter accepted");
        }
        ECKey key = (this.privateKey == null? this.publicKey : this.privateKey);
        if ((key != null) && !isCompatible((ECParameterSpec)params, key.getParams())) {
            throw new InvalidAlgorithmParameterException
                    ("Signature params does not match key params");
        }

        sigParams = (ECParameterSpec) params;
    }

    // get parameter, not supported. See JCA doc
    @Override
    @Deprecated
    protected Object engineGetParameter(String param)
            throws InvalidParameterException {
        throw new UnsupportedOperationException("getParameter() not supported");
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (sigParams == null) {
            return null;
        }
        try {
            AlgorithmParameters ap = CryptoInsts.getAlgorithmParameters("EC");
            ap.init(sigParams);
            return ap;
        } catch (Exception e) {
            // should never happen
            throw new ProviderException("Error retrieving EC parameters", e);
        }
    }
}
