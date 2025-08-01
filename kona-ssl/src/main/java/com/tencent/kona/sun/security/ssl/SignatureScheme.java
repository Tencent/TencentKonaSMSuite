/*
 * Copyright (c) 2015, 2025, Oracle and/or its affiliates. All rights reserved.
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

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;
import com.tencent.kona.sun.security.ssl.NamedGroup.NamedGroupSpec;
import com.tencent.kona.sun.security.ssl.X509Authentication.X509Possession;
import com.tencent.kona.sun.security.util.KeyUtil;
import com.tencent.kona.sun.security.util.SSLScope;
import com.tencent.kona.sun.security.util.SignatureUtil;

enum SignatureScheme {

    // ECDSA algorithms
    ECDSA_SECP256R1_SHA256  (0x0403, "ecdsa_secp256r1_sha256",
                                    "SHA256withECDSA",
                                    "EC",
                                    NamedGroup.SECP256_R1,
                                    ProtocolVersion.PROTOCOLS_TO_13),
    ECDSA_SECP384R1_SHA384  (0x0503, "ecdsa_secp384r1_sha384",
                                    "SHA384withECDSA",
                                    "EC",
                                    NamedGroup.SECP384_R1,
                                    ProtocolVersion.PROTOCOLS_TO_13),
    ECDSA_SECP521R1_SHA512  (0x0603, "ecdsa_secp521r1_sha512",
                                    "SHA512withECDSA",
                                    "EC",
                                    NamedGroup.SECP521_R1,
                                    ProtocolVersion.PROTOCOLS_TO_13),

    // SM algorithm
    SM2SIG_SM3              (0x0708, "sm2sig_sm3",
                                     "SM3withSM2",
                                     "EC",
                                     NamedGroup.CURVESM2,
                                     ProtocolVersion.PROTOCOLS_TO_TLCP),

    // EdDSA algorithms
    ED25519                 (0x0807, "ed25519", "Ed25519",
                                    "EdDSA",
                                    ProtocolVersion.PROTOCOLS_12_13),
    ED448                   (0x0808, "ed448", "Ed448",
                                    "EdDSA",
                                    ProtocolVersion.PROTOCOLS_12_13),

    // RSASSA-PSS algorithms with public key OID rsaEncryption
    //
    // The minimalKeySize is calculated as (See RFC 8017 for details):
    //     hash length + salt length + 16
    RSA_PSS_RSAE_SHA256     (0x0804, "rsa_pss_rsae_sha256",
                                    "RSASSA-PSS", "RSA",
                                    SigAlgParamSpec.RSA_PSS_SHA256, 528,
                                    ProtocolVersion.PROTOCOLS_12_13),
    RSA_PSS_RSAE_SHA384     (0x0805, "rsa_pss_rsae_sha384",
                                    "RSASSA-PSS", "RSA",
                                    SigAlgParamSpec.RSA_PSS_SHA384, 784,
                                    ProtocolVersion.PROTOCOLS_12_13),
    RSA_PSS_RSAE_SHA512     (0x0806, "rsa_pss_rsae_sha512",
                                    "RSASSA-PSS", "RSA",
                                    SigAlgParamSpec.RSA_PSS_SHA512, 1040,
                                    ProtocolVersion.PROTOCOLS_12_13),

    // RSASSA-PSS algorithms with public key OID RSASSA-PSS
    //
    // The minimalKeySize is calculated as (See RFC 8017 for details):
    //     hash length + salt length + 16
    RSA_PSS_PSS_SHA256      (0x0809, "rsa_pss_pss_sha256",
                                    "RSASSA-PSS", "RSASSA-PSS",
                                    SigAlgParamSpec.RSA_PSS_SHA256, 528,
                                    ProtocolVersion.PROTOCOLS_12_13),
    RSA_PSS_PSS_SHA384      (0x080A, "rsa_pss_pss_sha384",
                                    "RSASSA-PSS", "RSASSA-PSS",
                                    SigAlgParamSpec.RSA_PSS_SHA384, 784,
                                    ProtocolVersion.PROTOCOLS_12_13),
    RSA_PSS_PSS_SHA512      (0x080B, "rsa_pss_pss_sha512",
                                    "RSASSA-PSS", "RSASSA-PSS",
                                    SigAlgParamSpec.RSA_PSS_SHA512, 1040,
                                    ProtocolVersion.PROTOCOLS_12_13),

    // RSASSA-PKCS1-v1_5 algorithms
    RSA_PKCS1_SHA256        (0x0401, "rsa_pkcs1_sha256", "SHA256withRSA",
                                    "RSA", null, null, 511,
                                    ProtocolVersion.PROTOCOLS_TO_13,
                                    ProtocolVersion.PROTOCOLS_TO_12),
    RSA_PKCS1_SHA384        (0x0501, "rsa_pkcs1_sha384", "SHA384withRSA",
                                    "RSA", null, null, 768,
                                    ProtocolVersion.PROTOCOLS_TO_13,
                                    ProtocolVersion.PROTOCOLS_TO_12),
    RSA_PKCS1_SHA512        (0x0601, "rsa_pkcs1_sha512", "SHA512withRSA",
                                    "RSA", null, null, 768,
                                    ProtocolVersion.PROTOCOLS_TO_13,
                                    ProtocolVersion.PROTOCOLS_TO_12),

    // Legacy algorithms
    DSA_SHA256              (0x0402, "dsa_sha256", "SHA256withDSA",
                                    "DSA",
                                    ProtocolVersion.PROTOCOLS_TO_12),
    ECDSA_SHA224            (0x0303, "ecdsa_sha224", "SHA224withECDSA",
                                    "EC",
                                    ProtocolVersion.PROTOCOLS_TO_12),
    RSA_SHA224              (0x0301, "rsa_sha224", "SHA224withRSA",
                                    "RSA", 511,
                                    ProtocolVersion.PROTOCOLS_TO_12),
    DSA_SHA224              (0x0302, "dsa_sha224", "SHA224withDSA",
                                    "DSA",
                                    ProtocolVersion.PROTOCOLS_TO_12),
    ECDSA_SHA1              (0x0203, "ecdsa_sha1", "SHA1withECDSA",
                                    "EC",
                                    ProtocolVersion.PROTOCOLS_TO_13),
    RSA_PKCS1_SHA1          (0x0201, "rsa_pkcs1_sha1", "SHA1withRSA",
                                    "RSA", null, null, 511,
                                    ProtocolVersion.PROTOCOLS_TO_13,
                                    ProtocolVersion.PROTOCOLS_TO_12),
    DSA_SHA1                (0x0202, "dsa_sha1", "SHA1withDSA",
                                    "DSA",
                                    ProtocolVersion.PROTOCOLS_TO_12),
    RSA_MD5                 (0x0101, "rsa_md5", "MD5withRSA",
                                    "RSA", 511,
                                    ProtocolVersion.PROTOCOLS_TO_12);

    final int id;                       // hash + signature
    final String name;                  // literal name
    final String algorithm;             // signature algorithm
    final String keyAlgorithm;          // signature key algorithm
    private final SigAlgParamSpec signAlgParams;    // signature parameters
    private final NamedGroup namedGroup;    // associated named group

    // The minimal required key size in bits.
    //
    // Only need to check RSA algorithm at present. RSA keys of 512 bits
    // have been shown to be practically breakable, it does not make much
    // sense to use the strong hash algorithm for keys whose key size less
    // than 512 bits.  So it is not necessary to calculate the minimal
    // required key size exactly for a hash algorithm.
    //
    // Note that some provider may use 511 bits for 512-bit strength RSA keys.
    final int minimalKeySize;
    final List<ProtocolVersion> supportedProtocols;

    // Some signature schemes are supported in different versions for handshake
    // messages and certificates. This field holds the supported protocols
    // for handshake messages.
    final List<ProtocolVersion> handshakeSupportedProtocols;
    final boolean isAvailable;

    private static final String[] hashAlgorithms = new String[] {
            "none",         "md5",      "sha1",     "sha224",
            "sha256",       "sha384",   "sha512",   "sm3"
        };

    private static final String[] signatureAlgorithms = new String[] {
            "anonymous",    "rsa",      "dsa",      "ecdsa"
        };

    enum SigAlgParamSpec {   // support RSASSA-PSS only now
        RSA_PSS_SHA256 ("SHA-256", 32),
        RSA_PSS_SHA384 ("SHA-384", 48),
        RSA_PSS_SHA512 ("SHA-512", 64);

        private final AlgorithmParameterSpec parameterSpec;
        private final AlgorithmParameters parameters;
        private final boolean isAvailable;

        SigAlgParamSpec(String hash, int saltLength) {
            // See RFC 8017
            PSSParameterSpec pssParamSpec =
                    new PSSParameterSpec(hash, "MGF1",
                            new MGF1ParameterSpec(hash), saltLength, 1);
            AlgorithmParameters pssParams = null;

            boolean mediator = true;
            try {
                Signature signer = CryptoInsts.getSignature("RSASSA-PSS");
                signer.setParameter(pssParamSpec);
                pssParams = signer.getParameters();
            } catch (InvalidAlgorithmParameterException |
                    NoSuchAlgorithmException | RuntimeException exp) {
                // Signature.getParameters() may throw RuntimeException.
                mediator = false;
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning(
                        "RSASSA-PSS signature with " + hash +
                        " is not supported by the underlying providers", exp);
                }
            }

            this.isAvailable = mediator;
            this.parameterSpec = mediator ? pssParamSpec : null;
            this.parameters = mediator ? pssParams : null;
        }
    }

    // performance optimization
    // Handshake signature scope.
    static final Set<SSLScope> HANDSHAKE_SCOPE =
            Collections.singleton(SSLScope.HANDSHAKE_SIGNATURE);

    // Certificate signature scope.
    static final Set<SSLScope> CERTIFICATE_SCOPE =
            Collections.singleton(SSLScope.CERTIFICATE_SIGNATURE);

    // Non-TLS specific SIGNATURE CryptoPrimitive.
    private static final Set<CryptoPrimitive> SIGNATURE_PRIMITIVE_SET =
            Collections.singleton(CryptoPrimitive.SIGNATURE);

    // This ID, exactly TLSv1.3+GM+Cipher+Suite, is defined by RFC 8998.
    // It is only used by signature scheme sm2sig_sm3 for TLS 1.3 handshaking.
    private static final byte[] TLS13_SM2_ID = new byte[] {
            0x54, 0x4c, 0x53, 0x76, 0x31, 0x2e, 0x33, 0x2b,
            0x47, 0x4d, 0x2b, 0x43, 0x69, 0x70, 0x68, 0x65,
            0x72, 0x2b, 0x53, 0x75, 0x69, 0x74, 0x65};

    SignatureScheme(int id, String name,
            String algorithm, String keyAlgorithm,
            ProtocolVersion[] supportedProtocols) {
        this(id, name, algorithm, keyAlgorithm, -1, supportedProtocols);
    }

    SignatureScheme(int id, String name,
            String algorithm, String keyAlgorithm,
            int minimalKeySize,
            ProtocolVersion[] supportedProtocols) {
        this(id, name, algorithm, keyAlgorithm,
                null, minimalKeySize, supportedProtocols);
    }

    SignatureScheme(int id, String name,
            String algorithm, String keyAlgorithm,
            SigAlgParamSpec signAlgParamSpec, int minimalKeySize,
            ProtocolVersion[] supportedProtocols) {
        this(id, name, algorithm, keyAlgorithm,
                signAlgParamSpec, null, minimalKeySize,
                supportedProtocols, supportedProtocols);
    }

    SignatureScheme(int id, String name,
            String algorithm, String keyAlgorithm,
            NamedGroup namedGroup,
            ProtocolVersion[] supportedProtocols) {
        this(id, name, algorithm, keyAlgorithm,
                null, namedGroup, -1,
                supportedProtocols, supportedProtocols);
    }

    SignatureScheme(int id, String name,
            String algorithm, String keyAlgorithm,
            SigAlgParamSpec signAlgParams,
            NamedGroup namedGroup, int minimalKeySize,
            ProtocolVersion[] supportedProtocols,
            ProtocolVersion[] handshakeSupportedProtocols) {
        this.id = id;
        this.name = name;
        this.algorithm = algorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.signAlgParams = signAlgParams;
        this.namedGroup = namedGroup;
        this.minimalKeySize = minimalKeySize;
        this.supportedProtocols = Arrays.asList(supportedProtocols);
        this.handshakeSupportedProtocols =
                Arrays.asList(handshakeSupportedProtocols);

        boolean mediator = true;

        // An EC provider, for example the SunEC provider, may support
        // AlgorithmParameters but not KeyPairGenerator or Signature.
        //
        // Note: Please be careful if removing this block!
        if ("EC".equals(keyAlgorithm)) {
            mediator = JsseJce.isEcAvailable();
        }

        // Check the specific algorithm and parameters.
        if (mediator) {
            if (signAlgParams != null) {
                mediator = signAlgParams.isAvailable;
            } else {
                try {
                    CryptoInsts.getSignature(algorithm);
                } catch (Exception e) {
                    mediator = false;
                    if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                        SSLLogger.warning(
                            "Signature algorithm, " + algorithm +
                            ", is not supported by the underlying providers");
                    }
                }
            }
        }

        if (mediator && ((id >> 8) & 0xFF) == 0x03) {   // SHA224
            // There are some problems to use SHA224 on Windows.
            if (Security.getProvider("SunMSCAPI") != null) {
                mediator = false;
            }
        }

        this.isAvailable = mediator;
    }

    static SignatureScheme valueOf(int id) {
        for (SignatureScheme ss: SignatureScheme.values()) {
            if (ss.id == id) {
                return ss;
            }
        }

        return null;
    }

    static String nameOf(int id) {
        for (SignatureScheme ss: SignatureScheme.values()) {
            if (ss.id == id) {
                return ss.name;
            }
        }

        // Use TLS 1.2 style name for unknown signature scheme.
        int hashId = ((id >> 8) & 0xFF);
        int signId = (id & 0xFF);
        String hashName = (hashId >= hashAlgorithms.length) ?
            "UNDEFINED-HASH(" + hashId + ")" : hashAlgorithms[hashId];
        String signName = (signId >= signatureAlgorithms.length) ?
            "UNDEFINED-SIGNATURE(" + signId + ")" :
            signatureAlgorithms[signId];

        return signName + "_" + hashName;
    }

    // Note: the signatureSchemeName is not case-sensitive.
    static SignatureScheme nameOf(String signatureSchemeName) {
        for (SignatureScheme ss: SignatureScheme.values()) {
            if (ss.name.equalsIgnoreCase(signatureSchemeName)) {
                return ss;
            }
        }

        return null;
    }

    // Return the size of a SignatureScheme structure in TLS record
    static int sizeInRecord() {
        return 2;
    }

    private boolean isPermitted(
            SSLAlgorithmConstraints constraints, Set<SSLScope> scopes) {
        return constraints.permits(this.name, scopes)
                && constraints.permits(this.keyAlgorithm, scopes)
                && constraints.permits(this.algorithm, scopes)
                && constraints.permits(SIGNATURE_PRIMITIVE_SET, this.name, null)
                && constraints.permits(SIGNATURE_PRIMITIVE_SET, this.keyAlgorithm, null)
                && constraints.permits(SIGNATURE_PRIMITIVE_SET, this.algorithm,
                (signAlgParams != null ? signAlgParams.parameters : null))
                && (namedGroup == null || namedGroup.isPermitted(constraints));
    }

    // Helper method to update all locally supported signature schemes forAdd commentMore actions
    // a given HandshakeContext.
    static void updateHandshakeLocalSupportedAlgs(HandshakeContext hc) {
        // To improve performance we only update when necessary.
        // No need to do anything if we already computed the local supported
        // algorithms and either there is no negotiated protocol yet or the
        // only active protocol ends up to be the negotiated protocol.
        if (hc.localSupportedSignAlgs != null
                && hc.localSupportedCertSignAlgs != null
                && (hc.negotiatedProtocol == null
                || hc.activeProtocols.size() == 1)) {
            return;
        }

        List<ProtocolVersion> protocols = hc.negotiatedProtocol != null ?
                Collections.singletonList(hc.negotiatedProtocol) :
                hc.activeProtocols;

        hc.localSupportedSignAlgs = getSupportedAlgorithms(
                hc.sslConfig,
                hc.algorithmConstraints,
                protocols,
                HANDSHAKE_SCOPE);

        hc.localSupportedCertSignAlgs = getSupportedAlgorithms(
                hc.sslConfig,
                hc.algorithmConstraints,
                protocols,
                CERTIFICATE_SCOPE);
    }

    // Get local supported algorithm collection complying to algorithm
    // constraints and SSL scopes.
    private static List<SignatureScheme> getSupportedAlgorithms(
            SSLConfiguration config,
            SSLAlgorithmConstraints constraints,
            List<ProtocolVersion> activeProtocols,
            Set<SSLScope> scopes) {
        List<SignatureScheme> supported = new LinkedList<>();

        List<SignatureScheme> schemesToCheck =
                config.signatureSchemes == null ?
                        Arrays.asList(SignatureScheme.values()) :
                        namesOfAvailable(config.signatureSchemes);

        for (SignatureScheme ss: schemesToCheck) {
            if (!ss.isAvailable) {
                if (SSLLogger.isOn &&
                        SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest(
                        "Ignore unsupported signature scheme: " + ss.name);
                }
                continue;
            }

            boolean isMatch = false;
            for (ProtocolVersion pv : activeProtocols) {
                if (ss.isSupportedProtocol(pv, scopes)) {
                    isMatch = true;
                    break;
                }
            }

            if (isMatch) {
                if (ss.isPermitted(constraints, scopes)) {
                    supported.add(ss);
                } else if (SSLLogger.isOn &&
                        SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest(
                        "Ignore disabled signature scheme: " + ss.name);
                }
            } else if (SSLLogger.isOn &&
                    SSLLogger.isOn("ssl,handshake,verbose")) {
                SSLLogger.finest(
                    "Ignore inactive signature scheme: " + ss.name);
            }
        }

        return supported;
    }

    static List<SignatureScheme> getSupportedAlgorithms(
            SSLConfiguration config,
            SSLAlgorithmConstraints constraints,
            ProtocolVersion protocolVersion,
            int[] algorithmIds,
            Set<SSLScope> scopes) {
        List<SignatureScheme> supported = new LinkedList<>();
        for (int ssid : algorithmIds) {
            SignatureScheme ss = SignatureScheme.valueOf(ssid);
            if (ss == null) {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning(
                            "Unsupported signature scheme: " +
                            SignatureScheme.nameOf(ssid));
                }
            } else if ((config.signatureSchemes == null
                        || Utilities.contains(config.signatureSchemes, ss.name))
                    && ss.isAllowed(constraints, protocolVersion, scopes)) {
                supported.add(ss);
            }else {
                if (SSLLogger.isOn && SSLLogger.isOn("ssl,handshake")) {
                    SSLLogger.warning(
                            "Unsupported signature scheme: " + ss.name);
                }
            }
        }

        return supported;
    }

    static SignatureScheme getPreferableAlgorithm(
            SSLAlgorithmConstraints constraints,
            List<SignatureScheme> schemes,
            String keyAlgorithm,
            ProtocolVersion version) {

        for (SignatureScheme ss : schemes) {
            if (keyAlgorithm.equalsIgnoreCase(ss.keyAlgorithm)
                    && ss.isAllowed(constraints, version, HANDSHAKE_SCOPE)) {
                return ss;
            }
        }

        return null;
    }

    static Map.Entry<SignatureScheme, Signature> getSignerOfPreferableAlgorithm(
            SSLConfiguration sslConfig,
            SSLAlgorithmConstraints constraints,
            List<SignatureScheme> schemes,
            X509Possession x509Possession,
            ProtocolVersion version) {
        return getSignerOfPreferableAlgorithm(
                sslConfig, constraints, schemes,
                x509Possession.popPrivateKey,
                x509Possession.popCerts[0].getPublicKey(),
                x509Possession.getECParameterSpec(),
                version);
    }

    static Map.Entry<SignatureScheme, Signature> getSignerOfPreferableAlgorithm(
            SSLConfiguration sslConfig,
            SSLAlgorithmConstraints constraints,
            List<SignatureScheme> schemes,
            PrivateKey signingKey,
            PublicKey publicKey,
            ECParameterSpec params,
            ProtocolVersion version) {
        NamedGroup namedGroup = params != null
                ? NamedGroup.valueOf(params) : null;

        String keyAlgorithm = signingKey.getAlgorithm();
        int keySize;
        // Only need to check RSA algorithm at present.
        if (keyAlgorithm.equalsIgnoreCase("RSA") ||
                keyAlgorithm.equalsIgnoreCase("RSASSA-PSS")) {
            keySize = KeyUtil.getKeySize(signingKey);
        } else {
            keySize = Integer.MAX_VALUE;
        }
        for (SignatureScheme ss : schemes) {
            if (keySize >= ss.minimalKeySize &&
                    keyAlgorithm.equalsIgnoreCase(ss.keyAlgorithm) &&
                    ss.isAllowed(constraints, version, HANDSHAKE_SCOPE)) {
                if ((ss.namedGroup != null) && (ss.namedGroup.spec ==
                        NamedGroupSpec.NAMED_GROUP_ECDHE)) {
                    if (namedGroup == ss.namedGroup) {
                        Signature signer = ss.getSigner(signingKey,
                                publicKey, version.isTLS13());
                        if (signer != null) {
                            return new SimpleImmutableEntry<>(ss, signer);
                        }
                    }

                    if (SSLLogger.isOn &&
                            SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest(
                            "Ignore the signature algorithm (" + ss +
                            "), unsupported EC parameter spec: " + params);
                    }
                } else if ("EC".equals(ss.keyAlgorithm)) {
                    // Must be a legacy signature algorithm, which does not
                    // specify the associated named groups.  The connection
                    // cannot be established if the peer cannot recognize
                    // the named group used for the signature.  RFC 8446
                    // does not define countermeasures for the corner cases.
                    // In order to mitigate the impact, we choose to check
                    // against the local supported named groups.  The risk
                    // should be minimal as applications should not use
                    // unsupported named groups for its certificates.
                    if (params != null) {
                        NamedGroup keyGroup = NamedGroup.valueOf(params);
                        if (keyGroup != null &&
                                NamedGroup.isEnabled(sslConfig, keyGroup)) {
                            Signature signer = ss.getSigner(signingKey);
                            if (signer != null) {
                                return new SimpleImmutableEntry<>(ss, signer);
                            }
                        }
                    }

                    if (SSLLogger.isOn &&
                            SSLLogger.isOn("ssl,handshake,verbose")) {
                        SSLLogger.finest(
                            "Ignore the legacy signature algorithm (" + ss +
                            "), unsupported EC parameter spec: " + params);
                    }
                } else {
                    Signature signer = ss.getSigner(signingKey);
                    if (signer != null) {
                        return new SimpleImmutableEntry<>(ss, signer);
                    }
                }
            }
        }

        return null;
    }

    // Returns true if this signature scheme is supported for the given
    // protocol version and SSL scopes.
    private boolean isSupportedProtocol(
            ProtocolVersion version, Set<SSLScope> scopes) {
        if (scopes != null && scopes.equals(HANDSHAKE_SCOPE)) {
            return this.handshakeSupportedProtocols.contains(version);
        } else {
            return this.supportedProtocols.contains(version);
        }
    }

    // Returns true if this signature scheme is available, supported and
    // permitted for the given constraints, protocol version and SSL scopes.
    private boolean isAllowed(SSLAlgorithmConstraints constraints,
                              ProtocolVersion version, Set<SSLScope> scopes) {
        return isAvailable
                && isSupportedProtocol(version, scopes)
                && isPermitted(constraints, scopes);
    }

    static String[] getAlgorithmNames(Collection<SignatureScheme> schemes) {
        if (schemes != null) {
            ArrayList<String> names = new ArrayList<>(schemes.size());
            for (SignatureScheme scheme : schemes) {
                names.add(scheme.algorithm);
            }

            return names.toArray(new String[0]);
        }

        return new String[0];
    }

    private static List<SignatureScheme> namesOfAvailable(
            String[] signatureSchemes) {

        if (signatureSchemes == null || signatureSchemes.length == 0) {
            return Collections.emptyList();
        }

        List<SignatureScheme> sss = new ArrayList<>(signatureSchemes.length);
        for (String ss : signatureSchemes) {
            SignatureScheme scheme = SignatureScheme.nameOf(ss);
            if (scheme == null || !scheme.isAvailable) {
                if (SSLLogger.isOn &&
                        SSLLogger.isOn("ssl,handshake,verbose")) {
                    SSLLogger.finest(
                            "Ignore the signature algorithm (" + ss
                                    + "), unsupported or unavailable");
                }

                continue;
            }

            sss.add(scheme);
        }

        return sss;
    }

    // This method is used to get the signature instance of this signature
    // scheme for the specific public key.  Unlike getSigner(), the exception
    // is bubbled up.  If the public key does not support this signature
    // scheme, it normally means the TLS handshaking cannot continue and
    // the connection should be terminated.
    Signature getVerifier(PublicKey publicKey, boolean isTLS13)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException {
        if (!isAvailable) {
            return null;
        }

        Signature verifier = CryptoInsts.getSignature(algorithm);

        // sm2sig_sm3 uses "TLSv1.3+GM+Cipher+Suite" as ID for TLS 1.3.
        if (this == SM2SIG_SM3 && isTLS13) {
            verifier.setParameter(new SM2SignatureParameterSpec(
                    TLS13_SM2_ID, (ECPublicKey) publicKey));
        }

        SignatureUtil.initVerifyWithParam(verifier, publicKey,
                (signAlgParams != null ? signAlgParams.parameterSpec : null));

        return verifier;
    }

    Signature getVerifier(PublicKey publicKey)
            throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, InvalidKeyException {
        return getVerifier(publicKey, false);
    }

    // This method is also used to choose preferable signature scheme for the
    // specific private key.  If the private key does not support the signature
    // scheme, {@code null} is returned, and the caller may fail back to next
    // available signature scheme.
    Signature getSigner(PrivateKey privateKey, PublicKey publicKey, boolean isTLS13) {
        if (!isAvailable) {
            return null;
        }

        try {
            Signature signer = CryptoInsts.getSignature(algorithm);

            // sm2sig_sm3 always needs public key for signing.
            // And it uses "TLSv1.3+GM+Cipher+Suite" as ID for TLS 1.3.
            if (this == SM2SIG_SM3) {
                SM2SignatureParameterSpec paramSpec = isTLS13
                        ? new SM2SignatureParameterSpec(TLS13_SM2_ID,
                                (ECPublicKey) publicKey)
                        : new SM2SignatureParameterSpec((ECPublicKey) publicKey);
                signer.setParameter(paramSpec);
            }

            SignatureUtil.initSignWithParam(signer, privateKey,
                    (signAlgParams != null ?
                            signAlgParams.parameterSpec : null),
                    null);
            return signer;
        } catch (NoSuchAlgorithmException | InvalidKeyException |
                InvalidAlgorithmParameterException nsae) {
            if (SSLLogger.isOn &&
                    SSLLogger.isOn("ssl,handshake,verbose")) {
                SSLLogger.finest(
                        "Ignore unsupported signature algorithm (" +
                                this.name + ")", nsae);
            }
        }

        return null;
    }

    Signature getSigner(PrivateKey privateKey) {
        return getSigner(privateKey, null, false);
    }
}
