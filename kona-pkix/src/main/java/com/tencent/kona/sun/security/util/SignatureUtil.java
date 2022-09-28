/*
 * Copyright (c) 2018, 2022, Oracle and/or its affiliates. All rights reserved.
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

package com.tencent.kona.sun.security.util;

import java.io.IOException;
import java.security.*;
import java.security.spec.*;
import java.util.Locale;

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.jdk.internal.misc.SharedSecretsUtil;
import com.tencent.kona.sun.security.x509.AlgorithmId;
import com.tencent.kona.sun.security.rsa.RSAUtil;

/**
 * Utility class for Signature related operations. Currently used by various
 * internal PKI classes such as sun.security.x509.X509CertImpl,
 * sun.security.pkcs.SignerInfo, for setting signature parameters.
 *
 * @since   11
 */
public class SignatureUtil {

    /**
     * Convert OID.1.2.3.4 or 1.2.3.4 to its matching stdName, and return
     * upper case algorithm name.
     *
     * @param algName input, could be in any form
     * @return the matching algorithm name or the OID string in upper case.
     */
    private static String checkName(String algName) {
        algName = algName.toUpperCase(Locale.ENGLISH);
        if (algName.contains(".")) {
            // convert oid to String
            if (algName.startsWith("OID.")) {
                algName = algName.substring(4);
            }

            KnownOIDs ko = KnownOIDs.findMatch(algName);
            if (ko != null) {
                return ko.stdName().toUpperCase(Locale.ENGLISH);
            }
        }

        return algName;
    }

    // Utility method of creating an AlgorithmParameters object with
    // the specified algorithm name and encoding
    //
    // Note this method can be called only after converting OID.1.2.3.4 or
    // 1.2.3.4 to its matching stdName, which is implemented in the
    // checkName(String) method.
    private static AlgorithmParameters createAlgorithmParameters(String algName,
            byte[] paramBytes) throws ProviderException {

        try {
            algName = checkName(algName);
            AlgorithmParameters result =
                    CryptoInsts.getAlgorithmParameters(algName);
            result.init(paramBytes);
            return result;
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new ProviderException(e);
        }
    }

    /**
     * Utility method for converting the specified AlgorithmParameters object
     * into an AlgorithmParameterSpec object.
     *
     * @param sigName signature algorithm
     * @param params (optional) parameters
     * @return an AlgorithmParameterSpec, null if {@code params} is null
     */
    public static AlgorithmParameterSpec getParamSpec(String sigName,
            AlgorithmParameters params)
            throws ProviderException {

        AlgorithmParameterSpec paramSpec = null;
        if (params != null) {
            sigName = checkName(sigName);
            // AlgorithmParameters.getAlgorithm() may return oid if it's
            // created during DER decoding. Convert to use the standard name
            // before passing it to RSAUtil
            if (params.getAlgorithm().contains(".")) {
                try {
                    params = createAlgorithmParameters(sigName,
                        params.getEncoded());
                } catch (IOException e) {
                    throw new ProviderException(e);
                }
            }

            if (sigName.contains("RSA")) {
                paramSpec = RSAUtil.getParamSpec(params);
            } else if (sigName.contains("ECDSA")) {
                try {
                    paramSpec = params.getParameterSpec(ECParameterSpec.class);
                } catch (Exception e) {
                    throw new ProviderException("Error handling EC parameters", e);
                }
            } else {
                throw new ProviderException
                    ("Unrecognized algorithm for signature parameters " +
                     sigName);
            }
        }
        return paramSpec;
    }

    /**
     * Utility method for converting the specified parameter bytes
     * into an AlgorithmParameterSpec object.
     *
     * @param sigName signature algorithm
     * @param paramBytes (optional) parameter bytes
     * @return an AlgorithmParameterSpec, null if {@code paramBytes} is null
     */
    public static AlgorithmParameterSpec getParamSpec(String sigName,
            byte[] paramBytes)
            throws ProviderException {
        AlgorithmParameterSpec paramSpec = null;

        if (paramBytes != null) {
            sigName = checkName(sigName);
            if (sigName.contains("RSA")) {
                AlgorithmParameters params =
                    createAlgorithmParameters(sigName, paramBytes);
                paramSpec = RSAUtil.getParamSpec(params);
            } else if (sigName.contains("ECDSA")) {
                // Some certificates have params in an ECDSA algorithmID.
                // According to RFC 3279 2.2.3 and RFC 5758 3.2,
                // they are useless and should be ignored.
                return null;
            } else {
                throw new ProviderException
                     ("Unrecognized algorithm for signature parameters " +
                      sigName);
            }
        }
        return paramSpec;
    }

    // Utility method for initializing the specified Signature object
    // for verification with the specified key and params (may be null)
    public static void initVerifyWithParam(Signature s, PublicKey key,
            AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
//        SharedSecrets.getJavaSecuritySignatureAccess().initVerify(s, key, params);
        SharedSecretsUtil.secSignatureInitVerify(s, key, params);
    }

    // Utility method for initializing the specified Signature object
    // for verification with the specified Certificate and params (may be null)
    public static void initVerifyWithParam(Signature s,
            java.security.cert.Certificate cert,
            AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
//        SharedSecrets.getJavaSecuritySignatureAccess().initVerify(s, cert, params);
        SharedSecretsUtil.secSignatureInitVerify(s, cert, params);
    }

    // Utility method for initializing the specified Signature object
    // for signing with the specified key and params (may be null)
    public static void initSignWithParam(Signature s, PrivateKey key,
            AlgorithmParameterSpec params, SecureRandom sr)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
//        SharedSecrets.getJavaSecuritySignatureAccess().initSign(s, key, params, sr);
        SharedSecretsUtil.secSignatureInitSign(s, key, params, sr);
    }

    /**
     * Determines the digestEncryptionAlgorithmId in PKCS7 SignerInfo.
     *
     * @param signer Signature object that tells you RSASSA-PSS params
     * @param sigalg Signature algorithm
     * @param privateKey key tells you EdDSA params
     * @param directsign Ed448 uses different digest algs depending on this
     * @return the digest algId
     * @throws NoSuchAlgorithmException
     */
    public static AlgorithmId getDigestAlgInPkcs7SignerInfo(
            Signature signer, String sigalg, PrivateKey privateKey, boolean directsign)
            throws NoSuchAlgorithmException {
        AlgorithmId digAlgID;
        if (sigalg.equals("RSASSA-PSS")) {
            try {
                digAlgID = AlgorithmId.get(signer.getParameters()
                        .getParameterSpec(PSSParameterSpec.class)
                        .getDigestAlgorithm());
            } catch (InvalidParameterSpecException e) {
                throw new AssertionError("Should not happen", e);
            }
        } else {
            digAlgID = AlgorithmId.get(extractDigestAlgFromDwithE(sigalg));
        }
        return digAlgID;
    }

    /**
     * Extracts the digest algorithm name from a signature
     * algorithm name in either the "DIGESTwithENCRYPTION" or the
     * "DIGESTwithENCRYPTIONandWHATEVER" format.
     *
     * It's OK to return "SHA1" instead of "SHA-1".
     */
    public static String extractDigestAlgFromDwithE(String signatureAlgorithm) {
        signatureAlgorithm = signatureAlgorithm.toUpperCase(Locale.ENGLISH);
        int with = signatureAlgorithm.indexOf("WITH");
        if (with > 0) {
            return signatureAlgorithm.substring(0, with);
        } else {
            throw new IllegalArgumentException(
                    "Unknown algorithm: " + signatureAlgorithm);
        }
    }

    /**
     * Extracts the key algorithm name from a signature
     * algorithm name in either the "DIGESTwithENCRYPTION" or the
     * "DIGESTwithENCRYPTIONandWHATEVER" format.
     *
     * @return the key algorithm name, or null if the input
     *      is not in either of the formats.
     */
    public static String extractKeyAlgFromDwithE(String signatureAlgorithm) {
        signatureAlgorithm = signatureAlgorithm.toUpperCase(Locale.ENGLISH);
        int with = signatureAlgorithm.indexOf("WITH");
        String keyAlgorithm = null;
        if (with > 0) {
            int and = signatureAlgorithm.indexOf("AND", with + 4);
            if (and > 0) {
                keyAlgorithm = signatureAlgorithm.substring(with + 4, and);
            } else {
                keyAlgorithm = signatureAlgorithm.substring(with + 4);
            }
            if (keyAlgorithm.equalsIgnoreCase("ECDSA")) {
                keyAlgorithm = "EC";
            }
        }
        return keyAlgorithm;
    }

    /**
     * Returns default AlgorithmParameterSpec for a key used in a signature.
     * This is only useful for RSASSA-PSS now, which is the only algorithm
     * that must be initialized with a AlgorithmParameterSpec now.
     */
    public static AlgorithmParameterSpec getDefaultParamSpec(
            String sigAlg, Key k) {
        sigAlg = checkName(sigAlg);
        if (sigAlg.equalsIgnoreCase("RSASSA-PSS")) {
//            if (k instanceof RSAKey) {
//                AlgorithmParameterSpec spec = ((RSAKey) k).getParams();
//                if (spec instanceof PSSParameterSpec) {
//                    return spec;
//                }
//            }
//            switch (ifcFfcStrength(KeyUtil.getKeySize(k))) {
//                case "SHA256":
//                    return PSSParamsHolder.PSS_256_SPEC;
//                case "SHA384":
//                    return PSSParamsHolder.PSS_384_SPEC;
//                case "SHA512":
//                    return PSSParamsHolder.PSS_512_SPEC;
//                default:
//                    throw new AssertionError("Should not happen");
//            }
            throw new IllegalArgumentException("RSASSA-PSS is not supported");
        } else {
            return null;
        }
    }

    /**
     * Create a Signature that has been initialized with proper key and params.
     *
     * @param sigAlg signature algorithms
     * @param key private key
     * @param provider (optional) provider
     */
    public static Signature fromKey(String sigAlg, PrivateKey key, String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException,
                   InvalidKeyException{
        Signature sigEngine = (provider == null || provider.isEmpty())
                ? CryptoInsts.getSignature(sigAlg)
                : Signature.getInstance(sigAlg, provider);
        return autoInitInternal(sigAlg, key, sigEngine);
    }

    /**
     * Create a Signature that has been initialized with proper key and params.
     *
     * @param sigAlg signature algorithms
     * @param key private key
     * @param provider (optional) provider
     */
    public static Signature fromKey(String sigAlg, PrivateKey key, Provider provider)
            throws NoSuchAlgorithmException, InvalidKeyException{
        Signature sigEngine = (provider == null)
                ? CryptoInsts.getSignature(sigAlg)
                : Signature.getInstance(sigAlg, provider);
        return autoInitInternal(sigAlg, key, sigEngine);
    }

    private static Signature autoInitInternal(String alg, PrivateKey key, Signature s)
            throws InvalidKeyException {
        AlgorithmParameterSpec params = SignatureUtil
                .getDefaultParamSpec(alg, key);
        try {
            SignatureUtil.initSignWithParam(s, key, params, null);
        } catch (InvalidAlgorithmParameterException e) {
            throw new AssertionError("Should not happen", e);
        }
        return s;
    }

    /**
     * Derives AlgorithmId from a signature object and a key.
     * @param sigEngine the signature object
     * @param key the private key
     * @return the AlgorithmId, not null
     * @throws SignatureException if cannot find one
     */
    public static AlgorithmId fromSignature(Signature sigEngine, PrivateKey key)
            throws SignatureException {
        try {
            AlgorithmParameters params = null;
            try {
                params = sigEngine.getParameters();
            } catch (UnsupportedOperationException e) {
                // some provider does not support it
            }
            if (params != null) {
                return AlgorithmId.get(sigEngine.getParameters());
            } else {
                String sigAlg = sigEngine.getAlgorithm();
                if (sigAlg.equalsIgnoreCase("EdDSA")) {
                    // Hopefully key knows if it's Ed25519 or Ed448
                    sigAlg = key.getAlgorithm();
                }
                return AlgorithmId.get(sigAlg);
            }
        } catch (NoSuchAlgorithmException e) {
            // This could happen if both sig alg and key alg is EdDSA,
            // we don't know which provider does this.
            throw new SignatureException("Cannot derive AlgorithmIdentifier", e);
        }
    }

    /**
     * Checks if a signature algorithm matches a key, i.e. if this
     * signature can be initialized with this key. Currently used
     * in {@link jdk.security.jarsigner.JarSigner} to fail early.
     *
     * Note: Unknown signature algorithms are allowed.
     *
     * @param key must not be null
     * @param sAlg must not be null
     * @throws IllegalArgumentException if they are known to not match
     */
    public static void checkKeyAndSigAlgMatch(PrivateKey key, String sAlg) {
        String kAlg = key.getAlgorithm().toUpperCase(Locale.ENGLISH);
        sAlg = checkName(sAlg);
        switch (sAlg) {
            case "RSASSA-PSS":
                if (!kAlg.equals("RSASSA-PSS")
                        && !kAlg.equals("RSA")) {
                    throw new IllegalArgumentException(
                            "key algorithm not compatible with signature algorithm");
                }
                break;
            case "EDDSA":
                // General EdDSA, any EDDSA name variance is OK
                if (!kAlg.equals("EDDSA") && !kAlg.equals("ED448")
                        && !kAlg.equals("ED25519")) {
                    throw new IllegalArgumentException(
                            "key algorithm not compatible with signature algorithm");
                }
                break;
            default:
                if (sAlg.contains("WITH")) {
                    if ((sAlg.endsWith("WITHRSA") && !kAlg.equals("RSA")) ||
                            (sAlg.endsWith("WITHECDSA") && !kAlg.equals("EC")) ||
                            (sAlg.endsWith("WITHDSA") && !kAlg.equals("DSA"))) {
                        throw new IllegalArgumentException(
                                "key algorithm not compatible with signature algorithm");
                    }
                }
                // Do not fail now. Maybe new algorithm we don't know.
        }
    }

    /**
     * Returns the default signature algorithm for a private key.
     *
     * @param k cannot be null
     * @return the default alg, might be null if unsupported
     */
    public static String getDefaultSigAlgForKey(PrivateKey k) {
        String kAlg = k.getAlgorithm();
        switch (kAlg.toUpperCase(Locale.ENGLISH)) {
            case "DSA":
            case "RSA":
                return ifcFfcStrength(KeyUtil.getKeySize(k))
                    + "with" + kAlg;
            case "EC":
                return ecStrength(KeyUtil.getKeySize(k))
                    + "withECDSA";
            case "RSASSA-PSS":
            case "ED25519":
            case "ED448":
                return kAlg;
            default:
                return null;
        }
    }

//    // Useful PSSParameterSpec objects
//    private static class PSSParamsHolder {
//        static final PSSParameterSpec PSS_256_SPEC = new PSSParameterSpec(
//                "SHA-256", "MGF1",
//                MGF1ParameterSpec.SHA256,
//                32, PSSParameterSpec.TRAILER_FIELD_BC);
//        static final PSSParameterSpec PSS_384_SPEC = new PSSParameterSpec(
//                "SHA-384", "MGF1",
//                MGF1ParameterSpec.SHA384,
//                48, PSSParameterSpec.TRAILER_FIELD_BC);
//        static final PSSParameterSpec PSS_512_SPEC = new PSSParameterSpec(
//                "SHA-512", "MGF1",
//                MGF1ParameterSpec.SHA512,
//                64, PSSParameterSpec.TRAILER_FIELD_BC);
//    }

    // The following values are from SP800-57 part 1 rev 4 tables 2 and 3

    /**
     * Return the default message digest algorithm with the same security
     * strength as the specified EC key size.
     *
     * Attention: sync with the @implNote inside
     * {@link jdk.security.jarsigner.JarSigner.Builder#getDefaultSignatureAlgorithm}.
     */
    private static String ecStrength (int bitLength) {
        if (bitLength >= 512) { // 256 bits of strength
            return "SHA512";
        } else if (bitLength >= 384) {  // 192 bits of strength
            return "SHA384";
        } else { // 128 bits of strength and less
            return "SHA256";
        }
    }

    /**
     * Return the default message digest algorithm with the same security
     * strength as the specified IFC/FFC key size.
     *
     * Attention: sync with the @implNote inside
     * {@link jdk.security.jarsigner.JarSigner.Builder#getDefaultSignatureAlgorithm}.
     */
    private static String ifcFfcStrength (int bitLength) {
        if (bitLength > 7680) { // 256 bits
            return "SHA512";
        } else if (bitLength > 3072) {  // 192 bits
            return "SHA384";
        } else  { // 128 bits and less
            return "SHA256";
        }
    }
}
