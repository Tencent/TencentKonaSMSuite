package com.tencent.kona.ssl.interop;

import java.util.StringJoiner;

/*
 * Utilities for OpenSSL peers.
 */
public class OpenSSLUtils {

    public static String protocol(Protocol protocol) {
        if (protocol == null) {
            return null;
        }

        switch (protocol) {
        case TLSV1_2:
            return "tls1_2";

        case TLSV1_3:
            return "tls1_3";

        default:
            return null;
        }
    }

    public static String cipherSuite(CipherSuite cipherSuite) {
        switch (cipherSuite) {
        case TLS_AES_128_GCM_SHA256:
            return "TLS_AES_128_GCM_SHA256";

        case TLS_AES_256_GCM_SHA384:
            return "TLS_AES_256_GCM_SHA384";

        case TLS_SM4_GCM_SM3:
            return "TLS_SM4_GCM_SM3";

        case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
            return "ECDHE-ECDSA-AES128-SHA256";

        case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
            return "ECDHE-ECDSA-AES128-GCM-SHA256";

        default:
            return null;
        }
    }

    public static String cipherOption(CipherSuite... cipherSuites) {
        if (cipherSuites == null) {
            return null;
        }

        StringJoiner cipherOptions = new StringJoiner(":");
        StringJoiner cipherSuiteOptions = new StringJoiner(":");
        for(CipherSuite cipherSuite : cipherSuites) {
            String cipherOption = cipherSuite(cipherSuite);
            if (cipherOption != null) {
                if (cipherSuite.startProtocol != Protocol.TLSV1_3) {
                    cipherOptions.add(cipherOption);
                } else {
                    cipherSuiteOptions.add(cipherOption);
                }
            }
        }

        return Utilities.join(" ",
                Utilities.joinOptValue("-cipher", cipherOptions.toString()),
                Utilities.joinOptValue("-ciphersuites", cipherSuiteOptions.toString()));
    }

    public static String namedGroup(NamedGroup namedGroup) {
        switch (namedGroup) {
            case SECP256R1:
                return "P-256";

            case CURVESM2:
                return "SM2";

            default:
                return null;
        }
    }

    public static String signatureScheme(SignatureScheme signatureScheme) {
        switch (signatureScheme) {
            case ECDSA_SECP256R1_SHA256:
                return "ecdsa_secp256r1_sha256";

            case SM2SIG_SM3:
                return "sm2sig_sm3";

            default:
                return null;
        }
    }

    public static String joinNamedGroups(NamedGroup... namedGroups) {
        return Utilities.join(":", OpenSSLUtils::namedGroup, namedGroups);
    }

    public static String joinSignatureSchemes(SignatureScheme... signatureSchemes) {
        return Utilities.join(":", OpenSSLUtils::signatureScheme, signatureSchemes);
    }
}
