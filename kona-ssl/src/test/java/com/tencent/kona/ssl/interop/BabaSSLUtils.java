package com.tencent.kona.ssl.interop;

/*
 * Utilities for OpenSSL/BabaSSL peers.
 */
public class BabaSSLUtils {

    public static String cipherSuite(CipherSuite cipherSuite) {
        switch (cipherSuite) {
            case TLCP_ECC_SM4_CBC_SM3:
                return "ECC-SM2-SM4-CBC-SM3";

            case TLCP_ECDHE_SM4_CBC_SM3:
                return "ECDHE-SM2-SM4-CBC-SM3";

            case TLCP_ECC_SM4_GCM_SM3:
                return "ECC-SM2-SM4-GCM-SM3";

            case TLCP_ECDHE_SM4_GCM_SM3:
                return "ECDHE-SM2-SM4-GCM-SM3";

            default:
                return null;
        }
    }
}
