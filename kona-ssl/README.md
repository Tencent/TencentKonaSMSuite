# Tencent Kona SSL

## Introduction
Tencent Kona SSL is a java security provider, which is named `KonaSSL`. This provider implements China's GB/T 38636-2020 specification based on Java Secure Socket Extension（[JSSE]）framework. And it also applies ShangMi algorithms to TLS 1.3 based on [RFC 8998].

For providing the above features, `KonaSSL` implements the JDK-specified Service Provider Interfaces (SPIs), such as CertificateFactorySpi，KeyStoreSpi，CertPathBuilderSpi，SignatureSpi，KeyAgreementSpi and SSLContextSpi.

## Usages
Now that `KonaSSL` is based on the JDK-specific SPIs, then the usages are the same as those SPIs, say SSLContext. Understanding JSSE really helps, so please read the official [reference].

### Loading
Before using any feature in `KonaSSL`, it has to load `KonaSSLProvider`. And `KonaCryptoProvider` and `KonaPKIXProvider` must be loaded as well.

```
Security.addProvider(new KonaCryptoProvider());
Security.addProvider(new KonaPKIXProvider());
Security.addProvider(new KonaSSLProvider());
```

The above lines adds the three providers at the bottom of the provider list. That means their privilege are the lowest. If necessary, it can insert the providers at specific positions, like the below, 

```
Security.insertProviderAt(new KonaCryptoProvider(), position1);
Security.insertProviderAt(new KonaPKIXProvider(), position2);
Security.insertProviderAt(new KonaSSLProvider(), position3);
```

the less the position values are, the higher the priorities are. The minimum value is 1.

### Create SSLContext
In order to take advantage of the implementations on TLCP and RFC 8998 in `KonaSSL`, the most important point is taking SSLSocket or SSLEngine to apply the SSLContext implementation from `KonaSSL`.

```
KeyStore trustStore = <a trust store carring the CAs>;
TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
tmf.init(trustStore);

KeyStore keyStore = <a key store carring the end entity certificates>;
KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
kmf.init(keyStore, keyStorePassword);

SSLContext context = SSLContext.getInstance("TLCPv1.1");
context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
```

When create SSLContext instances, it allows to specify the following context protocols:

- TLSv1.2, which represents only TLS 1.2 is supported.
- TLSv1.3, which represents only TLS 1.3 is supported.
- TLS, which represents TLS 1.3 and TLS 1.2 are supported.
- TLCPv1.1, which represents only TLCP 1.1 is supported.
- TLCP, which represents TLCP 1.1, TLS 1.3 and TLS 1.2 are supported.

Please read the official [SSLContext] reference for understanding it deeply.


[JSSE]:
<https://docs.oracle.com/en/java/javase/11/security/java-secure-socket-extension-jsse-reference-guide.html#GUID-93DEEE16-0B70-40E5-BBE7-55C3FD432345>

[RFC 8998]:
<https://datatracker.ietf.org/doc/html/rfc8998>

[JSSE reference]:
<https://docs.oracle.com/en/java/javase/11/security/java-secure-socket-extension-jsse-reference-guide.html#GUID-93DEEE16-0B70-40E5-BBE7-55C3FD432345>

[SSLContext]:
<https://docs.oracle.com/en/java/javase/11/security/java-secure-socket-extension-jsse-reference-guide.html#GUID-C281CAF3-275F-4DE4-8B47-4A84363CF39F>
