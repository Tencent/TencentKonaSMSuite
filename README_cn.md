[![Release](https://img.shields.io/badge/Release-1.0.13-brightgreen)](https://github.com/Tencent/TencentKonaSMSuite/releases/tag/v1.0.13)
[![Maven Central](https://img.shields.io/badge/Maven_Central-gray)](https://central.sonatype.com/search?q=com.tencent.kona)

**[English]** | 中文

# 腾讯Kona国密套件

## 概览

腾讯Kona国密套件是一组Java安全特性的Provider实现，主要服务于Java生态中的国密应用场景。具体地，该套件包含有四个Provider：

- [KonaCrypto]，它遵循标准的[JCA]框架实现了国密密码学算法SM2，SM3和SM4。
- [KonaPKIX]，它实现了国密证书的解析与验证，并可加载和创建包含国密证书的密钥库。它需要依赖`KonaCrypto`。另外，该组件还提供了两个工具类：
  - KeyTool，它的功能与JDK中的`keytool`相同，可以生成密钥对，创建证书以及密钥库。它支持使用`PBEWithHmacSM3AndSM4`算法对私钥和密钥库进行加密，也可使用`HmacPBESM3`算法验证密钥库的完整性。
  - KeyStoreTool，它可以将已有的[PEM]格式的私钥和证书导入密钥库。
- [KonaSSL]，它实现了中国的传输层密码协议（TLCP），并遵循RFC 8998规范将国密基础算法应用到了TLS 1.3协议中。它需要依赖`KonaCrypto`和`KonaPKIX`。
- [Kona]，它将`KonaCrypto`，`KonaPKIX`和`KonaSSL`中的特性进行了简单的封装，所以它需要根据实际需求去依赖这些Provider中的一个或多个。一般地，**建议使用这个Provider**。

本项目还提供了一个Spring Boot模块，即[kona-demo]，作为服务端的示例。该模块演示了将腾讯Kona国密套件集成入第三方Web服务器，包括`Jetty`和`Tomcat`，的途径。但该模块并不是本项目的制品之一。另外，`kona-ssl`模块的[测试集]还提供了与`Netty`，`gRPC`，`Apache HttpClient`和`OkHttp`进行集成的示例。

## 系统要求

### 操作系统
腾讯Kona国密套件为纯Java语言编写，可以运行在任何支持JDK的操作系统上。

### JDK
腾讯Kona国密套件支持JDK的全部四个长期支持（LTS）版本，即8，11，17和21。

注意：已经使用Oracle颁发的JCE代码签名[证书]对本套组件的jar文件签名，所以它们也可以运行在Oracle JDK上。

欢迎使用腾讯的OpenJDK发行版，即Tencent Kona JDK，提供[8]，[11]和[17]三大版本，支持Linux，macOS和Windows等主流操作系统以及x86_64和aarch64等主流CPU架构。**最新的Tencent Kona JDK 8已经原生地支持了国密密码学算法，国密SSL/TLCP协议和RFC 8998规范。**

### Android
默认情况下，腾讯Kona国密套件并不需要依赖JDK的任何内部API实现，所以它也可以运行Android平台上。

## 安装
腾讯Kona国密套件的所有制品（jar文件）都已经上传到了[Maven中央仓库]。一般地，只需要在项目的构建脚本中把它们声明为依赖就可以了。比如，在[Gradle]的构建脚本中可以有如下的依赖声明，

```
repositories {
    mavenCentral()
}

dependencies {
    implementation("com.tencent.kona:kona-crypto:<version>")
    implementation("com.tencent.kona:kona-pkix:<version>")
    implementation("com.tencent.kona:kona-ssl:<version>")
    implementation("com.tencent.kona:kona-provider:<version>")
}
```

注意，并不一定要将所有的Provider都加到类路径中，请根据实际需求去声明依赖。例如，只需要使用国密的密码学算法，且想使用Provider名称`Kona`时，那么依赖声明可能就像下面这样，

```
dependencies {
    implementation("com.tencent.kona:kona-crypto:<version>")
    implementation("com.tencent.kona:kona-provider:<version>")
}
```

## 构建
腾讯Kona国密套件使用Gradle进行构建，其脚本使用[Kotlin DSL]。该Gradle项目包含有四个子模块，即*kona-crypto*，*kona-pkix*，*kona-ssl*和*kona-provider*，它们分别对应于四个Provider，即`KonaCrypto`，`KonaPKIX`，`KonaSSL`和`Kona`。

构建该项目的一个典型方法就是在项目的根目录下执行命令：

```
./gradlew build
```

它会编译源代码，并执行单元测试，最后制作出jar文件。也可以仅构建某个子模块，比如像下面这样：

```
./gradlew :kona-pkix:build
```

## 贡献
非常欢迎与我们一起改进和维护腾讯Kona国密套件，请阅读[CONTRIBUTING.md]以了解如何报告缺陷，安全漏洞，提出需求和贡献代码。

## 许可协议
腾讯Kona国密套件使用的许可协议是GNU GPL v2.0 license with classpath exception，请详见附带的许可协议[文本]。

## 常见问题
**问**：为何使用SM2 Cipher时会遇到异常`java.security.InvalidKeyException: Illegal key size or default parameters`？<br>
**答**：在JDK `8u161`之前，JDK默认不能支持较强的加密算法和密钥长度。它们就不能支持256位长度的加密算法，如`AES-256`。而SM2加密算法的密钥长度也是256，所以也存在这个问题。具体解决方法，请见这个[Stack Overflow的问题]。

**问**：能否在TLS 1.2中支持`ECC_SM4_GCM_SM3`和`ECDHE_SM4_GCM_SM3`？<br>
**答**：由于没有任何RFC规范将国密密码套件引入TLS 1.2协议，所以无法在该协议中支持上述密码套件。但本项目基于RFC 8998支持在TLS 1.3协议中使用国密密码套件`TLS_SM4_GCM_SM3`。

**问**：是否支持`GMSSL`或`GMSSL 1.1`协议？<br>
**答**：国家标准GB/T 38636-2020定义的这个类TLS安全通信协议是`传输层密码协议`，其英文为`Transport layer cryptography protocol`。本组件使用它的简称`TLCP`，版本为`1.1`。而`TLCP`或`TLCP 1.1`就是`GMSSL`或`GMSSL 1.1`。

**问**：为什么不能在Oracle JDK下执行本项目中的测试用例？<br>
**答**：Oracle JDK会验证JCE实现（此处为`KonaCrypto`）是否被签名，并且其关联的证书要由JCE Code Signing CA颁发。而在执行本项目中的测试用例时，其使用的`KonaCrypto` Provider还没有签名，所以不能在Oracle JDK中执行它们。但发布到Maven中央仓库中的jar文件都被签名了，所以它们都可以在Oracle JDK中运行。

**问**：本项目与BoucyCastle中的国密实现有何关系？<br>
**答**：本项目的早期版本会依赖BouncyCastle中的国密密码学算法，但从`1.0.5`版开始，已经不再对BouncyCastle有任何的依赖。由于都是遵循中国相关标准来实现的国密密码学算法，所以这两个组件之间可以正常交互。另外，需要了解的是，BouncyCastle并不支持国密安全通信协议，包括TLCP和TLS 1.3/RFC 8998。

**问**：可以支持的JDK 8最低版本是多少？<br>
**答**：根据不同的应用场景，对JDK 8的版本的要求也不尽相同。
- 仅使用国密密码学算法和/或TLCP协议，最多需要`8u141`（甚至更老的版本)。
  - 要在TLCP协议中使用ALPN扩展，要求的最低版本则为`8u251`。
- 为了使用TLS 1.3/RFC 8998协议，要求的最低版本为`8u261`。

你所遇到的问题，之前可能已经有人提出来过了。在提出新的问题之前，请先浏览这些已有的[问题]。

[English]:
<README.md>

[JCA]:
<https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html>

[KonaCrypto]:
<kona-crypto/README_cn.md>

[KonaPKIX]:
<kona-pkix/README_cn.md>

[PEM]:
<https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail>

[KonaSSL]:
<kona-ssl/README_cn.md>

[Kona]:
<kona-provider/README_cn.md>

[kona-demo]:
<kona-demo/README_cn.md>

[测试集]:
<kona-ssl/src/test/java/com/tencent/kona/ssl/demo>

[证书]:
<https://www.oracle.com/java/technologies/javase/getcodesigningcertificate.html#jcacodesigning>

[8]:
<https://github.com/Tencent/TencentKona-8>

[11]:
<https://github.com/Tencent/TencentKona-11>

[17]:
<https://github.com/Tencent/TencentKona-17>

[Maven中央仓库]:
<https://repo1.maven.org/maven2/com/tencent/kona/>

[Gradle]:
<https://gradle.org>

[Kotlin DSL]:
<https://docs.gradle.org/current/userguide/kotlin_dsl.html>

[CONTRIBUTING.md]:
<CONTRIBUTING_cn.md>

[文本]:
<LICENSE.txt>

[Stack Overflow的问题]:
<https://stackoverflow.com/questions/3862800/invalidkeyexception-illegal-key-size>

[问题]:
<https://github.com/Tencent/TencentKonaSMSuite/issues?q=is%3Aissue+label%3Aquestion>
