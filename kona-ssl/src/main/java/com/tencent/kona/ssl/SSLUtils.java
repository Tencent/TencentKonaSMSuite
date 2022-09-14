package com.tencent.kona.ssl;

import com.tencent.kona.crypto.CryptoInsts;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

/**
 * The utilities for this provider.
 */
public class SSLUtils {

    /* ***** System properties start ***** */

    public static String getPropCertListFormat() {
        return System.getProperty("com.tencent.kona.ssl.certListFormat");
    }

    // SIGN|ENC|CA, SIGN|CA|ENC
    public static void setPropCertListFormat(String format) {
        String certListFormat = format == null || format.length() == 0
                ? "" : format.toUpperCase(Locale.ENGLISH);
        System.setProperty("com.tencent.kona.ssl.certListFormat", certListFormat);
    }

    /* ***** System properties end ***** */

    public static KeyPairGenerator getECKeyPairGenerator(String namedGroup)
            throws NoSuchAlgorithmException {
        String algorithm = "curvesm2".equalsIgnoreCase(namedGroup)
                ? "SM2" : "EC";
        return CryptoInsts.getKeyPairGenerator(algorithm);
    }
}
