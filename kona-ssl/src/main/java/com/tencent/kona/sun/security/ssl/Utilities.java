package com.tencent.kona.sun.security.ssl;

import java.nio.charset.StandardCharsets;

public class Utilities extends com.tencent.kona.sun.security.util.Utilities {

    // The ID used by TLS 1.3 handshaking with signature scheme SM3withSM2.
    public static final byte[] TLS13_SM_ID
            = "TLSv1.3+GM+Cipher+Suite".getBytes(StandardCharsets.ISO_8859_1);
}
