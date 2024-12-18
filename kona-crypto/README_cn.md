**[English]** | 中文

# 腾讯Kona Crypto

## 简介
腾讯Kona Crypto包含两个Java Security Provider，一个是`KonaCrypto`，另一个是`KonaCrypto-Native`。它们遵循相关的国家标准实现了如下的国密基础算法：

- SM2，它是一个基于[椭圆曲线(ECC)]的公钥加密算法，在实现该算法时遵循了如下的国家标准：
  - GB/T 32918.1-2016 第1部分：总则
  - GB/T 32918.2-2016 第2部分：数字签名
  - GB/T 32918.3-2016 第3部分：密钥交换协议
  - GB/T 32918.4-2016 第4部分：公钥加密算法
  - GB/T 32918.5-2017 第5部分：参数定义
- SM3，它是一个密码学安全的哈希算法，在实现该算法时遵循了如下的国家标准：
  - GB/T 32905-2016 SM3密码杂凑算法
- SM4，它是一个分组加密算法，在实现该算法时遵循了如下的国家标准：
  - GB/T 32907-2016 SM4分组密码算法

为了提供上述特性，这些Provider基于JDK标准的[Java Cryptography Architecture (JCA)]框架，实现了JDK定义的KeyPairGeneratorSpi，SignatureSpi，CipherSpi，MessageDigestSpi，MacSpi和KeyAgreementSpi等Service Provider Interface (SPI)。

## 实现方式

目前提供了纯Java语言实现的`KonaCrypto` Provider，以及基于JNI与OpenSSL实现的`KonaCrypto-Native` Provider。后者仅支持`Linux x86_64/aarch64`平台。本项目默认使用的OpenSSL版本为3.4.0，但可以支持3.0及之后的版本。

可以使用系统属性`com.tencent.kona.openssl.crypto.lib.path`去指定使用其他的OpenSSL crypto库文件（`libcrypto.so`），该系统属性的值是一个本地绝对路径。

## 使用

应用程序使用`KonaCrypto`和`KonaCrypto-Native`的方法完全相同，所以本文仅以`KonaCrypto`为例来描述用法。

由于`KonaCrypto`是基于JCA框架的，所以在使用风格上，与其它的JCA实现（如JDK自带的[SunJCE]和[SunEC]）是一样的。正常地，应用程序并不需要直接访问`KonaCrypto`中的算法实现类，而是通过相关的JDK API去调用指定算法的实现。了解JCA的设计原理与代码风格，对于应用`KonaCrypto`是非常有帮助的，请阅读官方的[参考指南]。

### 加载
在使用`KonaCrypto`中的任何特性之前，必须要加载`KonaCryptoProvider`，

```
Security.addProvider(new KonaCryptoProvider());
```

上面的方法会将这个Provider加到整个Provider列表的最后一位，其优先级则为最低。如有必要，可以使用下面的方法将它们插入到Provider列表的指定位置，

```
Security.insertProviderAt(new KonaCryptoProvider(), position);
```

position的值越小，代表的优先级越高，最小可为1。然而，并不推荐提升该Provider的优先级，故推荐使用`Security.addProvider`。

### SM2

#### 密钥对
生成SM2密钥对与生成JDK自带的其它算法（如EC）密钥对的方式是完全相同的，仅需要调用标准的JDK API就可以了。`KonaCrypto`提供了两个`KeyPairGenerator`实现去生成SM2密钥对：

- JDK自带的`ECKeyPairGenerator`。它生成的密钥对中，私钥格式为`PKCS#8`，公钥格式为`X.509`。
- 新引入的`SM2KeyPairGenerator`。它生成的密钥对中，私钥和公钥格式均为`RAW`。私钥长度为32字节。公钥为长度为65字节，格式为`04||x||y`，其中`04`表示非压缩格式，`x`和`y`分别为该公钥点在椭圆曲线上的仿射横坐标和纵坐标的值。

创建使用`ECKeyPairGenerator`的`KeyPairGenerator`实例。

```
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC);
keyPairGenerator.initialize(spec);
```

其中，`spec`可以为`SM2ParameterSpec`（使用`SM2ParameterSpec.instance()`创建它的实例）或者是`ECGenParameterSpec`（使用`new ECGenParameterSpec("curveSM2")`创建它的实例）。

若创建使用`SM2KeyPairGenerator`的`KeyPairGenerator`实例，则代码如下。

```
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SM2);
```

生成密钥对。

```
KeyPair keyPair = keyPairGenerator.generateKeyPair();
ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
```

关于密钥对生成器API的更详细用法，请参考[KeyPairGenerator]的官方文档。

#### 准备公钥与私钥
一般情况下，在签名和加密操作中，都是使用已有的密钥对，并不需要临时生成。所以需要像下面那样，读取公钥与私钥数据，分别生成PublicKey和PrivateKey对象。

```
byte[] encodedPublicKey = <编码形式的公钥>;
byte[] encodedPrivateKey = <编码形式的私钥>;

KeyFactory keyFactory = KeyFactory.getInstance("SM2");

SM2PublicKeySpec publicKeySpec = new SM2PublicKeySpec(encodedPublicKey);
PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(encodedPrivateKey);
PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
```

#### 签名
使用SM2签名算法与使用JDK自带的其它签名算法（如ECDSA）的方式是非常相似的，但在参数设置上需要使用自定义API。

创建Signature实例。

```
Signature signature = Signature.getInstance("SM2);
```

使用私钥进行初始化，以准备进行签名操作。

```
signature.initSign(privateKey);
```

上面使用的是一种简约的初始化方式，它会使用默认的SM2 ID，即`1234567812345678`。它还会使用私钥去计算出公钥，因为根据规范，公钥也要参与签名值的计算过程，这是与国际签名算法（如ECDSA）的一个重大不同点。但计算公钥会有一定的开销，对性能会有负面影响。

如果要使用非默认ID，或者不希望额外地计算公钥，则在初始化时之前需要额外设置一个定制的AlgorithmParameterSpec实例，即SM2SignatureParameterSpec。

```
byte[] altID = <定制化的ID>;
ECPublicKey publicKey = <公钥>;
SM2SignatureParameterSpec paramSpec = new SM2SignatureParameterSpec(altID, publicKey);
signature.setParameter(paramSpec);
signature.initSign(privateKey);
```

参数设置与初始化完成之后，就可以传入被签名的消息数据了。

```
byte[] message = <被签名的消息数据>;
signature.update(message);
```

生成签名值。

```
byte[] sign = signature.sign();
```

SM2签名值使用ASN.1格式进行编码，其长度在71到73字节之间。

使用公钥进行初始化，以准备进行验签操作。

```
signature.initVerify(publicKey);
```

传入被签名的消息数据。

```
byte[] message = <被签名的消息数据>;
signature.update(message);
```

再传入已生成的签名值进行验证，

```
boolean verified = signature.verify(sign);
```

如果验证成功，返回true，否则返回false。

必须要注意的是，私钥用于签名，公钥用于验签。关于签名算法API的更详细用法，请参考[Signature]的官方文档。

#### 加密
出于性能考虑，与其它的非对称加密算法（如RSA和EC）相同，SM2加密算法一般只用于加密少量的关键性数据。

创建Cipher实例，

```
Cipher cipher = Cipher.getInstance("SM2");
```

使用公钥对Cipher进行初始化，指定其使用加密模式。

```
cipher.init(Cipher.ENCRYPT_MODE, publicKey);
```

传入消息数据生成密文。

```
byte[] message = <被加密的消息数据>;
byte[] ciphertext = cipher.doFinal(message);
```

使用私钥对Cipher进行初始化，指定其使用解密模式。

```
cipher.init(Cipher.DECRYPT_MODE, privateKey);
```

传入密文生成明文。

```
byte[] cleartext = cipher.doFinal(ciphertext);
```

必须要注意的是，公钥用于加密，私钥用于解密。关于加密算法API的更详细用法，请参考[Cipher]的官方文档。

### SM3
使用SM3算法与使用JDK自带的其它哈希算法（如SHA-256）的方式是完全相同的，仅需要调用JDK API就可以生成消息摘要（哈希值）。

创建MessageDigest实例。

```
MessageDigest md = MessageDigest.getInstance("SM3");
```

可以一次性输入全部消息数据，然后生成消息摘要。

```
byte[] message = <消息数据>;
byte[] digest = md.digest(message);
```

也可以分多次传递消息数据的片断，最后再生成消息摘要。

```
byte[] messageSegment1 = <消息数据片断1>;
byte[] messageSegment2 = <消息数据片断2>;

// 多次传入消息数据片断
md.update(messageSegment1);
md.update(messageSegment2);

// 最后再生成消息摘要
byte[] digest = md.digest();
```

关于消息摘要算法API的更详细用法，请参考[MessageDigest]的官方文档。

### HmacSM3
使用HmacSM3算法与使用JDK自带的其它消息验证码算法（如HmacSHA256）的方式是完全相同的，仅需要调用JDK API就可以生成消息验证码。

准备密钥，其长度为16字节。

```
byte[] key = <密钥>;
SecretKey secretKey = new SecretKeySpec(key, "SM4");
```

创建Mac实例。

```
Mac hmac = Mac.getInstance("HmacSM3");
```

使用密钥对Mac进行初始化。

```
hmac.init(secretKey);
```

一次性传入消息数据，并生成消息验证码，其长度固定为32字节。

```
byte[] message = <消息>;
byte[] mac = hmac.doFinal(message);
```

还可以分多次传入消息数据的片断，最后再生成消息验证码，

```
byte[] messageSegment1 = <消息数据片断1>;
byte[] messageSegment2 = <消息数据片断2>;

// 多次传入消息数据片断
hmac.update(messageSegment1);
hmac.update(messageSegment2);

// 最后再生成消息验证码
byte[] mac = hmac.doFinal();
```

关于消息验证码算法API的更详细用法，请参考[Mac]的官方文档。

### SM4
使用SM4算法与使用JDK自带的其它分组加密算法（如AES）的方式是完全相同的，仅需要调用JDK API就可以进行SM4加密和解密操作。`KonaCrypto`支持了SM4的四种分组操作模式，包括CBC，CTR，ECB和GCM，同时还支持了PKCS#7填充规范。

准备密钥，其长度为16字节。

```
byte[] key = <密钥>;
SecretKey secretKey = new SecretKeySpec(key, "SM4");
```

创建Cipher实例。

```
Cipher cipher = Cipher.getInstance(transformation);
```

其中的transformation是一个由算法名，分组操作模式和填充规范这三个部分拼接而成的参数组合，各个参数部分之间使用`/`分隔。

支持如下的参数组合：
- SM4/CBC/NoPadding：使用CBC分组操作模式，不使用填充。明文或密文的长度必须是16字节的整数倍。
- SM4/CBC/PKCS7Padding：使用CBC分组操作模式，且使用PKCS#7填充。明文或密文的长度可以不是16字节的整数倍。
- SM4/CTR/NoPadding：使用CTR分组操作模式，不使用填充。明文或密文的长度可以不是16字节的整数倍。
- SM4/ECB/NoPadding：使用ECB分组操作模式，不使用填充。明文或密文的长度必须是16字节的整数倍。
- SM4/ECB/PKCS7Padding：使用ECB分组操作模式，且使用PKCS#7填充。明文或密文的长度可以不是16字节的整数倍。
- SM4/GCM/NoPadding：使用GCM分组操作模式，不使用填充。明文或密文的长度可以不是16字节的整数倍。

构建算法参数。

```
AlgorithmParameterSpec paramSpec = <算法参数实现类>;
```

不同的操作模式需要不同类型的算法参数实现类，

- CBC和CTR模式需要[IvParameterSpec]，创建它的实例时需要一个16字节长度的初始化向量（IV）。
- GCM模式需要[GCMParameterSpec]，创建它的实例时需要指定tag长度为128比特，并使用一个12字节长度的初始化向量（IV）。

使用密钥和算法参数对Cipher进行初始化，指定其使用加密模式。

```
cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
```

一次性传入全部的消息数据，并生成密文。

```
byte[] ciphertext = cipher.doFinal(message);
```

使用密钥和算法参数对Cipher进行初始化，指定使用解密模式。

```
cipher.init(Cipher.DECRYPT_MODE, secretKey);
```

一次性传入全部密文数据，并生成明文。

```
byte[] cleartext = cipher.doFinal(ciphertext);
```

另外，还可以分多次传入明文/密文片断，则分多次的获取对应的密文/明文片断，

```
byte[] input1 = <明文/密文片断1>;
byte[] input2 = <明文/密文片断2>;

// 多次传入明文/密文片断，并多次生成密文/明文片断
byte[] output1 = cipher.update(input1);
byte[] output2 = cipher.update(input2);

// 生成最后部分的密文/明文片断
byte[] outputFinal = cipher.doFinal();
```

关于加密算法API的更详细用法，请参考[Cipher]的官方文档。


[English]:
<README.md>

[Java Cryptography Architecture (JCA)]:
<https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html#GUID-2BCFDD85-D533-4E6C-8CE9-29990DEB0190>

[SunJCE]:
<https://docs.oracle.com/en/java/javase/11/security/oracle-providers.html#GUID-A47B1249-593C-4C38-A0D0-68FA7681E0A7>

[SunEC]:
<https://docs.oracle.com/en/java/javase/11/security/oracle-providers.html#GUID-091BF58C-82AB-4C9C-850F-1660824D5254>

[JCA的参考指南]:
<https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html#GUID-2BCFDD85-D533-4E6C-8CE9-29990DEB0190>

[椭圆曲线(ECC)]:
<https://en.wikipedia.org/wiki/Elliptic-curve_cryptography>

[KeyPairGenerator]:
<https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html#GUID-7EA29AC2-28B5-405D-BD2F-7055EC9E1EDD>

[MessageDigest]:
<https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html#GUID-FB0090CA-2BCC-4D2C-BD2F-6F0A97197BD7>

[MAC]:
<https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html#GUID-8E014689-EBBB-4DE1-B6E0-24CE59AD8B9A>

[Cipher]:
<https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html#GUID-94225C88-F2F1-44D1-A781-1DD9D5094566>

[Signature]:
<https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html#GUID-9CF09CE2-9443-4F4E-8095-5CBFC7B697CF>

[IvParameterSpec]:
<https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/spec/IvParameterSpec.html>

[GCMParameterSpec]:
<https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/spec/GCMParameterSpec.html>
