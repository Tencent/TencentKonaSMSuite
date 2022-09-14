# 腾讯Kona PKIX

## 简介
腾讯Kona PKIX是一个Java安全Provider实现，其Provider名称为`KonaPKIX`。它基于OpenJDK的Public Key Infrastructure（PKI）特性实现了对使用国密算法（SM2椭圆曲线和SM3withSM2签名算法）的X.509证书的解析，以及证书链验证。

为了提供上述特性，`KonaPKIX`实现了JDK定义的CertificateFactorySpi，KeyStoreSpi，CertPathBuilderSpi和SignatureSpi等Service Provider Interface (SPI)。

## 使用
由于`KonaPKIX`是基于JDK定义的标准SPI，所以在使用风格上，与使用JDK自带的同等特性（如CertificateFactory）是完全相同的。了解JDK的PKI的编程风格，对于应用`KonaPKIX`是非常在帮助的。请阅读官方的[参考指南]。

### 加载
在使用`KonaPKIX`中的任何特性之前，必须要加载`KonaPKIXProvider`，同时也需要加载`KonaCryptoProvider`，

```
Security.addProvider(new KonaCryptoProvider());
Security.addProvider(new KonaPKIXProvider());
```

上面的方法会将这两个Provider加到整个Provider列表的最后两位，其优先级则为最低。如有必要，可以使用下面的方法将它们插入到Provider列表的指定位置，

```
Security.insertProviderAt(new KonaCryptoProvider(), position1);
Security.insertProviderAt(new KonaPKIXProvider(), position2);
```

position的值越小，代表的优先级越高，最小可为1。

### 证书
`KonaPKIX`能够解析标准的X.509证书，支持RSA与EC证书，特别是支持了包含国密算法（SM2曲线和SM3withSM2签名算法）的EC证书。

```
String certPEM = <证书的PEM格式文本>;
CertificateFactory cf = CertificateFactory.getInstance("X.509");
X509Certificate certificate = (X509Certificate) cf.generateCertificate(
        new ByteArrayInputStream(certPEM.getBytes(StandardCharsets.UTF_8));
```

关于证书解析的更详细说明，请阅读[CertificateFactory]的官方参考指南。

### 公钥
可以从证书中获取公钥，支持RSA与EC公钥。

```
PublicKey publicKey = certificate.getPublicKey();
```

publicKey可强制类型转换为RSAPublicKey或ECPublicKey.

### 私钥
`KonaPKIX`能够解析标准的PKCS#8私钥，支持RSA与EC私钥。

```
String peyPEM = <PKCS#8私钥的PEM格式文本>;
PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
        Base64.getMimeDecoder().decode(keyPem));
KeyFactory keyFactory = KeyFactory.getInstance("EC");
PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
```

privateKey可强制类型转换为RSAPrivateKey或ECPrivateKey。

### 签名
利用生成的X.509证书（公钥）和PKCS#8私钥，可以进行签名与验签操作。

创建Signature实例，使用SM3withSM2算法。

```
Signature signature = Signature.getInstance("SM3withSM2");
```

使用私钥对消息数据进行签名，生成签名数据。

```
signature.initSign(privateKey);
signature.update(message);
byte[] sign = signature.sign();
```

使用证书验证签名数据，以确定是否验证通过。

```
signature.initVerify(certificate);
signature.update(message);
boolean verified = signature.verify(sign);
```

使用证书去验证签名时，要求证书的key usage中包含有digitalSignature。如果不使用证书，也可以直接使用公钥去验证签名数据。

```
signature.initVerify(publicKey);
signature.update(message);
boolean verified = signature.verify(sign);
```

### KeyStore
一般地，证书及其私钥应该存放在密钥库文件中，以便于管理与分发。`KonaPKIX`支持标准的PKCS#12格式的密钥库，也支持JDK自定义的JKS格式的密钥库。

准备证书与私钥。

```
X509Certificate caCertificate = <CA证书>;

X509Certificate eeCertificate = <终端实体证书>;
PrivateKey eePrivateKey = <终端实体证书关联的私钥>;
```

创建KeyStore实例，使用标准的PKCS#12格式。

```
KeyStore keyStore = KeyStore.getInstance("PKCS12");
keyStore.load(null, null);
```

加入CA证书，并指定一个别名。

```
keyStore.setCertificateEntry("ca", caCertificate);
```

加入终端实体证书及其私钥，需要一个密码去保护私钥。

```
byte[] keyPassword = <保护私钥的密码>;
keyStore.setKeyEntry(
        "ee",
        eePrivateKey,
        keyPassword,
        new Certificate[] { caCertificate } );
```

可以将KeyStore实例保存到本地文件，需要指定一个密码去保护这个密钥库文件的完整性。

```
File keyStoreFile = <本地密钥库文件>;
byte[] keyStorePassword = <保护密钥库文件的密码>;
try (FileOutputStream out = new FileOutputStream(keyStoreFile)) {
    keyStore.store(out, keyStorePassword);
}
```

下次再创建KeyStore实例时，直接加载这个密钥库文件就可以了。

```
KeyStore localKeyStore = KeyStore.getInstance("PKCS12");
try (FileInputStream keyStoreIn
        = new FileInputStream(keyStoreFile)) {
    localKeyStore.load(keyStoreIn, keyStorePassword);
} 
```


[参考指南]:
<https://docs.oracle.com/en/java/javase/11/security/java-pki-programmers-guide.html#GUID-650D0D53-B617-4055-AFD3-AF5C2629CBBF>

[CertificateFactory]:
<https://docs.oracle.com/en/java/javase/11/security/java-pki-programmers-guide.html#GUID-BCABADD4-C0DC-4987-B187-F086B4BCE195>

[CertPathValidator]:
<https://docs.oracle.com/en/java/javase/11/security/java-pki-programmers-guide.html#GUID-808C1A6D-6A67-4026-A9DE-223A428EC80A>
