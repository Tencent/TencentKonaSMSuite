package com.tencent.kona.pkix;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

/**
 * The Kona PKIX Provider.
 */
public class KonaPKIXProvider extends Provider {

    private static final long serialVersionUID = 1207190468265916803L;

    private static final String INFO = "Kona PKIX Provider "
            + "supporting ShangMi certificate and validation";

    static final String NAME = "KonaPKIX";

    private static final double VERSION_NUM = 1.0D;

    public KonaPKIXProvider() {
        super(NAME, VERSION_NUM, INFO);

        AccessController.doPrivileged(
                (PrivilegedAction<Void>) () -> {
                    putEntries(this);

                    return null;
                });
    }

    private static void putEntries(Provider provider) {
        provider.put("CertificateFactory.X.509",
                "com.tencent.kona.sun.security.provider.X509Factory");

        provider.put("KeyStore.PKCS12",
                "com.tencent.kona.sun.security.pkcs12.PKCS12KeyStore");
        provider.put("KeyStore.JKS",
                "com.tencent.kona.sun.security.provider.JavaKeyStore$JKS");

        provider.put("CertPathValidator.PKIX",
                "com.tencent.kona.sun.security.provider.certpath.PKIXCertPathValidator");
        provider.put("CertPathBuilder.PKIX",
                "com.tencent.kona.sun.security.provider.certpath.SunCertPathBuilder");
        provider.put("CertStore.Collection",
                "com.tencent.kona.sun.security.provider.certpath.CollectionCertStore");
    }
}
