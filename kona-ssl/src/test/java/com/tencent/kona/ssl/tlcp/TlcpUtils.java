package com.tencent.kona.ssl.tlcp;

import com.tencent.kona.ssl.interop.FileCert;
import com.tencent.kona.ssl.interop.HashAlgorithm;
import com.tencent.kona.ssl.interop.KeyAlgorithm;
import com.tencent.kona.ssl.interop.SignatureAlgorithm;

/**
 * The utilities for testing TLCP.
 */
public class TlcpUtils {

    public static final FileCert CA_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "tlcp",
            "tlcp-ca.crt",
            "tlcp-ca.key");

    public static final FileCert INTCA_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "tlcp",
            "tlcp-intca.crt",
            "tlcp-intca.key");

    // sign and enc cert (Server)
    public static final FileCert SERVER_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "tlcp",
            "tlcp-server.crt",
            "tlcp-server.key");

    // sign and enc cert (Client)
    public static final FileCert CLIENT_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "tlcp",
            "tlcp-client.crt",
            "tlcp-client.key");

    // sign cert (Server)
    public static final FileCert SERVER_SIGN_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "tlcp",
            "tlcp-server-sign.crt",
            "tlcp-server-sign.key");

    // sign cert (Client)
    public static final FileCert CLIENT_SIGN_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "tlcp",
            "tlcp-client-sign.crt",
            "tlcp-client-sign.key");

    // enc cert (Server)
    public static final FileCert SERVER_ENC_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "tlcp",
            "tlcp-server-enc.crt",
            "tlcp-server-enc.key");

    // enc cert (Client)
    public static final FileCert CLIENT_ENC_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "tlcp",
            "tlcp-client-enc.crt",
            "tlcp-client-enc.key");
}
