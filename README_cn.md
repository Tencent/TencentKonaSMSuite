# 腾讯Kona国密套件

## 概览

腾讯Kona国密套件是一组Java安全特性的Provider实现，主要服务于Java生态中的国密应用场景。具体地，该套件包含有四个Provider：

- [KonaCrypto]，它遵循标准的[JCA]框架实现了国密基础算法SM2，SM3和SM4。
- [KonaPKIX]，它实现了国密证书的解析与验证，并可加载和创建包含国密证书的密钥库文件。
- [KonaSSL]，它实现了中国的传输层密码协议（TLCP），并遵循RFC 8998规范将国密基础算法应用到了TLS 1.3协议中。
- [Kona]，它将`KonaCrypto`，`KonaPKIX`和`KonaSSL`中的特性进行了简单的封装。一般地，建议使用这个Provider。

## 系统要求

### 操作系统
腾讯Kona国密套件为纯Java语言编写，可以运行在任何支持OpenJDK的操作系统上。

### JDK版本
腾讯Kona国密套件支持OpenJDK的全部三个长期支持（LTS）版本，即8，11和17。

注意：由于Oracle JDK要求运行在其上的JCE实现需要获得Oracle公司颁发的[证书]，而腾讯Kona国密套件目前还没有申请该证书，所以该套组件暂时无法运行在Oracle JDK上。推荐使用腾讯的OpenJDK发行版，即Tencent Kona JDK，提供[8]，[11]和[17]三大版本，支持Linux，macOS和Windows等主流操作系统平台。

## 构建
腾讯Kona国密套件使用[Gradle]进行构建，其脚本使用[Kotlin DSL]。该Gradle项目包含有四个子模块，即*kona-crypto*，*kona-pkix*，*kona-ssl*和*kona-provider*，它们分别对应于四个Provider，即`KonaCrypto`，`KonaPKIX`，`KonaSSL`和`Kona`。

构建该项目的一个典型方法就是在项目的根目录下执行命令：

```
gradle build
```

它会编译源代码，并执行单元测试，最后制作出jar文件。也可以仅构建某个子模块，比如像下面这样：

```
gradle :kona-pkix:build
```

## 贡献
非常欢迎与我们一起改进和维护腾讯Kona国密套件，请阅读[CONTRIBUTING.md]以了解如何报告缺陷，提出需求和贡献代码。

## 许可协议
腾讯Kona国密套件使用的许可协议是GNU GPL v2.0 license with classpath exception，请详见本项目附带的该许可协议[文本]。


[JCA]:
<https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html>

[KonaCrypto]:
<kona-crypto/README_cn.md>

[KonaPKIX]:
<kona-pkix/README_cn.md>

[KonaSSL]:
<kona-ssl/README_cn.md>

[Kona]:
<kona-provider/README_cn.md>

[证书]:
<https://www.oracle.com/java/technologies/javase/getcodesigningcertificate.html#jcacodesigning>

[8]:
<https://github.com/Tencent/TencentKona-8>

[11]:
<https://github.com/Tencent/TencentKona-11>

[17]:
<https://github.com/Tencent/TencentKona-17>

[Gradle]:
<https://gradle.org>

[Kotlin DSL]:
<https://docs.gradle.org/current/userguide/kotlin_dsl.html>

[CONTRIBUTING.md]:
<CONTRIBUTING_cn.md>

[文本]:
<LICENSE.txt>
