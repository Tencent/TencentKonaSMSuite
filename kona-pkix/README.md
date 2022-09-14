# Tencent Kona PKIX

## Introduction
Tencent Kona PKIX is a Java security provider, which is named `KonaPKIX`. Based on OpenJDK Public Key Infrastructure (PKI) features, it supports ShangMi algorithms (SM2 curve and SM3withSM2 signature) on X.509 certificates parsing and certificate chain verifying.

For providing the above features, `KonaPKIX` implements the JDK-specified Service Provider Interfaces (SPIs), such as CertificateFactorySpi，KeyStoreSpi，CertPathBuilderSpi and SignatureSpi.

## Usages
Now that `KonaPKIX` is based on the JDK-specific SPIs, then the usages are the same as those SPIs, say CertificateFactory. Understanding JDK PKI really helps, so please read the official [reference].

### Loading
Before using any feature in `KonaPKIX`, it has to load `KonaPKIXProvider`. And `KonaCryptoProvider` must be loaded as well.

```
Security.addProvider(new KonaCryptoProvider());
Security.addProvider(new KonaPKIXProvider());
```

The above lines add these providers at the bottom of the provider list. That means their privilege are the lowest. If necessary, it can insert the providers at specific positions, like the below, 

```
Security.insertProviderAt(new KonaCryptoProvider(), position1);
Security.insertProviderAt(new KonaPKIXProvider(), position2);
```

the less the positions are, the higher the priorities are. The minimum value is 1.

### Certificate
`KonaPKIX` can parse X.509 certificates, including RSA and EC certificates. Especially, it supports the EC certificates using ShangMi algorithms, like SM2 curve and SM3withSM2 signature.

```
String certPEM = <certificate in PEM format>;
CertificateFactory cf = CertificateFactory.getInstance("X.509");
X509Certificate certificate = (X509Certificate) cf.generateCertificate(
        new ByteArrayInputStream(certPEM.getBytes(StandardCharsets.UTF_8));
```

For more information on certificate parsing, please read the official reference on [CertificateFactory].

### Public key
It can parse public key from the certificates and supports RSA and EC algorithms.

```
PublicKey publicKey = certificate.getPublicKey();
```

publicKey can be cast to RSAPublicKey or ECPublicKey.


### Private key
It can parse private key from PKCS#8 format and support RSA and EC algorithms.

```
String peyPEM = <private key in PKCS#8 format>;
PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
        Base64.getMimeDecoder().decode(keyPem));
KeyFactory keyFactory = KeyFactory.getInstance("EC");
PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
```

privateKey can be cast to RSAPrivateKey or ECPrivateKey.

### Signature
It can sign data with PKCS#8 private key and verify the signature with X.509 certificate.

Create Signature instance and use SM3withSM2 signature algorithm.

```
Signature signature = Signature.getInstance("SM3withSM2");
```

Sign the message with the private key and generate the signature data.

```
signature.initSign(privateKey);
signature.update(message);
byte[] sign = signature.sign();
```

Verify the signature data with the certificate and determine whether the verification passes or fails.

```
signature.initVerify(certificate);
signature.update(message);
boolean verified = signature.verify(sign);
```

The certificate has to contain digitalSignature key usage for verifying signature data. But it also can verify the signature with the public key directly.

```
signature.initVerify(publicKey);
signature.update(message);
boolean verified = signature.verify(sign);
```

### KeyStore
Generally, certificates and private keys are stored in key store files so that they can be managed and distributed easily. 

Load certificates and private key.

```
X509Certificate caCertificate = <CA certificate>;

X509Certificate eeCertificate = <end entity certificate;
PrivateKey eePrivateKey = <the private key associated with the end entity certificate>;
```

Create KeyStore instance and use PKCS#12 type.

```
KeyStore keyStore = KeyStore.getInstance("PKCS12");
keyStore.load(null, null);
```

Add the CA certificate and give it an alias.

```
keyStore.setCertificateEntry("ca", caCertificate);
```

Add the end entity certificate and the associated private key. And provide a password to protect the private key.

```
byte[] keyPassword = <the password protecting the private key>;
keyStore.setKeyEntry(
        "ee",
        eePrivateKey,
        keyPassword,
        new Certificate[] { caCertificate } );
```

It can save a KeyStore instance to a local file. A password is needed to protect the integrity of the key store file.

```
File keyStoreFile = <the local key store file>;
byte[] keyStorePassword = <the password>;
try (FileOutputStream out = new FileOutputStream(keyStoreFile)) {
    keyStore.store(out, keyStorePassword);
}
```

Then it can create the KeyStore instance from the key store file.

```
KeyStore localKeyStore = KeyStore.getInstance("PKCS12");
try (FileInputStream keyStoreIn
        = new FileInputStream(keyStoreFile)) {
    localKeyStore.load(keyStoreIn, keyStorePassword);
} 
```


[reference]:
<https://docs.oracle.com/en/java/javase/11/security/java-pki-programmers-guide.html#GUID-650D0D53-B617-4055-AFD3-AF5C2629CBBF>

[CertificateFactory]:
<https://docs.oracle.com/en/java/javase/11/security/java-pki-programmers-guide.html#GUID-BCABADD4-C0DC-4987-B187-F086B4BCE195>

[CertPathValidator]:
<https://docs.oracle.com/en/java/javase/11/security/java-pki-programmers-guide.html#GUID-808C1A6D-6A67-4026-A9DE-223A428EC80A>
