package com.tencent.kona.ssl;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

/**
 * The Kona SSL/TLS Provider.
 */
public class KonaSSLProvider extends Provider {

    private static final long serialVersionUID = 1207190468265916803L;

    private static final String INFO = "Kona SSL/TLS Provider "
            + "supporting RFC 8998 and Transport Layer Cryptography Protocol (TLCP)";

    static final String NAME = "KonaSSL";

    private static final double VERSION_NUM = 1.0D;

    public KonaSSLProvider() {
        super(NAME, VERSION_NUM, INFO);

        AccessController.doPrivileged(
                (PrivilegedAction<Void>) () -> {
                    putEntries(this);

                    return null;
                });
    }

    private static void putEntries(Provider provider) {
        provider.put("KeyManagerFactory.SunX509",
                "com.tencent.kona.sun.security.ssl.KeyManagerFactoryImpl$SunX509");
        provider.put("KeyManagerFactory.NewSunX509",
                "com.tencent.kona.sun.security.ssl.KeyManagerFactoryImpl$X509");

        provider.put("TrustManagerFactory.SunX509",
                "com.tencent.kona.sun.security.ssl.TrustManagerFactoryImpl$SimpleFactory");
        provider.put("TrustManagerFactory.PKIX",
                "com.tencent.kona.sun.security.ssl.TrustManagerFactoryImpl$PKIXFactory");
        provider.put("Alg.Alias.TrustManagerFactory.SunPKIX", "PKIX");
        provider.put("Alg.Alias.TrustManagerFactory.X509", "PKIX");
        provider.put("Alg.Alias.TrustManagerFactory.X.509", "PKIX");

        provider.put("SSLContext.TLCPv1.1",
                "com.tencent.kona.sun.security.ssl.TLCPContextImpl$TLCP11Context");
        provider.put("SSLContext.TLSv1.2",
                "com.tencent.kona.sun.security.ssl.SSLContextImpl$TLS12Context");
        provider.put("SSLContext.TLSv1.3",
                "com.tencent.kona.sun.security.ssl.SSLContextImpl$TLS13Context");

        provider.put("SSLContext.TLCP",
                "com.tencent.kona.sun.security.ssl.TLCPContextImpl$TLCPContext");
        provider.put("SSLContext.TLS",
                "com.tencent.kona.sun.security.ssl.SSLContextImpl$TLSContext");
        provider.put("Alg.Alias.SSLContext.SSL", "TLS");

        provider.put("SSLContext.Default",
                "com.tencent.kona.sun.security.ssl.SSLContextImpl$DefaultSSLContext");

        provider.put("KeyGenerator.SunTlsPrf",
                "com.tencent.kona.sun.security.provider.TlsPrfGenerator$V10");
        provider.put("KeyGenerator.SunTls12Prf",
                "com.tencent.kona.sun.security.provider.TlsPrfGenerator$V12");

        provider.put("KeyGenerator.SunTlsMasterSecret",
                "com.tencent.kona.sun.security.provider.TlsMasterSecretGenerator");
        provider.put("Alg.Alias.KeyGenerator.SunTls12MasterSecret",
                "SunTlsMasterSecret");
        provider.put("Alg.Alias.KeyGenerator.SunTlsExtendedMasterSecret",
                "SunTlsMasterSecret");

        provider.put("KeyGenerator.SunTlsKeyMaterial",
                "com.tencent.kona.sun.security.provider.TlsKeyMaterialGenerator");
        provider.put("Alg.Alias.KeyGenerator.SunTls12KeyMaterial",
                "SunTlsKeyMaterial");

        provider.put("KeyGenerator.TlcpKeyMaterial",
                "com.tencent.kona.sun.security.provider.TlcpKeyMaterialGenerator");
        provider.put("Alg.Alias.KeyGenerator.TlcpKeyMaterial", "TlcpKeyMaterial");

        provider.put("KeyGenerator.TlcpSM2PremasterSecret",
                "com.tencent.kona.sun.security.provider.TlcpSM2PremasterSecretGenerator");
        provider.put("Alg.Alias.KeyGenerator.TlcpSM2PremasterSecret",
                "TlcpSM2PremasterSecret");

        provider.put("KeyGenerator.TlcpMasterSecret",
                "com.tencent.kona.sun.security.provider.TlcpMasterSecretGenerator");
        provider.put("Alg.Alias.KeyGenerator.TlcpMasterSecret",
                "TlcpMasterSecret");

        provider.put("KeyGenerator.TlcpPrf",
                "com.tencent.kona.sun.security.provider.TlcpPrfGenerator");
    }
}
