# 腾讯Kona SSL

## 简介
腾讯Kona SSL是一个Java安全特性Provider实现，其Provider名称为`KonaSSL`。它基于OpenJDK的Java Secure Socket Extension（[JSSE]）框架实现了由国家标准GB/T 38636-2020规定的TLCP协议，并遵循[RFC 8998]规范将国密算法应用于TLS 1.3协议。

为了提供上述特性，`KonaSSL`实现了JDK定义的SSLContextSpi等Service Provider Interface（SPI）。

## 使用
由于`KonaSSL`是基于JDK定义的标准SPI，所以在使用风格上，与使用JDK自带的同等特性（如SSLContext）是完全相同的。了解JDK的JSSE的编程风格，对于应用`KonaSSL`是非常在帮助的。请阅读官方的[参考指南]。

### 加载
在使用`KonaSSL`中的任何特性之前，必须要进行加载`KonaSSLProvider`，同时也需要加载`KonaCryptoProvider`和`KonaPKIXProvider`，

```
Security.addProvider(new KonaCryptoProvider());
Security.addProvider(new KonaPKIXProvider());
Security.addProvider(new KonaSSLProvider());
```

上面的方法会将这三个Provider加到整个Provider列表的最后三位，其优先级则为最低。如有必要，可以使用下面的方法将它们插入到Provider列表的指定位置，

```
Security.insertProviderAt(new KonaCryptoProvider(), position1);
Security.insertProviderAt(new KonaPKIXProvider(), position2);
Security.insertProviderAt(new KonaSSLProvider(), position3);
```

position的值越小，代表的优先级越高，最小可为1。

### 创建SSLContext
为了能利用上`KonaSSL`实现的国标TLCP协议和RFC 8998规范等特性，其关键就是让JDK的SSLSocket或SSLEngine能利用上`KonaSSL`实现的SSLContext实例。

```
KeyStore trustStore = <包含CA证书的密钥库文件>;
TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
tmf.init(trustStore);

KeyStore keyStore = <包含终端实体证书的密钥库文件>;
KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
kmf.init(keyStore, keyStorePassword);

SSLContext context = SSLContext.getInstance("TLCPv1.1");
context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
```

在创建SSLContext实例时，允许指定如下的Context Protocol：

- TLSv1.2，表示仅支持TLS 1.2协议。
- TLSv1.3，表示仅支持TLS 1.3协议。
- TLS，表示支持TLS 1.3和TLS 1.2协议。
- TLCPv1.1，表示仅支持TLCP 1.1协议。
- TLCP，表示支持TLCP 1.1，TLS 1.3和TLS 1.2协议。

请阅读[SSLContext]的官方参考指南，以便于能更深入地理解它。


[JSSE]:
<https://docs.oracle.com/en/java/javase/11/security/java-secure-socket-extension-jsse-reference-guide.html#GUID-93DEEE16-0B70-40E5-BBE7-55C3FD432345>

[RFC 8998]:
<https://datatracker.ietf.org/doc/html/rfc8998>

[参考指南]:
<https://docs.oracle.com/en/java/javase/11/security/java-secure-socket-extension-jsse-reference-guide.html#GUID-93DEEE16-0B70-40E5-BBE7-55C3FD432345>

[SSLContext]:
<https://docs.oracle.com/en/java/javase/11/security/java-secure-socket-extension-jsse-reference-guide.html#GUID-C281CAF3-275F-4DE4-8B47-4A84363CF39F>
