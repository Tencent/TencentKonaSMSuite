# Tencent Kona SM Suite

## Overview

Tencent Kona SM Suite is a set of Java security providers, which service the ShangMi applications in Java ecosystem. This suite contains four providers:

- [KonaCrypto]，which implements SM2, SM3 and SM4 algorithms based on Java Cryptography Architecture.
- [KonaPKIX]，which supports ShangMi algorithms on loading certificate and certificate chain verification. It also can load and write key store files containing ShangMi certificates.
- [KonaSSL] implements China's Transport Layer Cryptographic Protocol, and also applies ShangMi algorithms to TLS 1.3 based on RFC 8998.
- [Kona], which wraps all the features in `KonaCrypto`，`KonaPKIX` and `KonaSSL`, so it has to depend on one or more of them. Generally, **this provider is recommended**.

In addition, this project provides a Spring Boot application, exactly [kona-demo], as a server-side demo. But this module is not one of the artifacts of this project.

## System requirements

### Operating systems
Tencent Kona SM Suite is 100% Java-coded, so it can run on any operating systems that can run JDK.

### JDK
Tencent Kona SM Suite supports all the JDK long-term supported (LTS) releases, namely 8, 11 and 17.

Please note Tencent Kona SM Suite is already signed by Oracle-issued JCE code signing [certificate], so it also can run on Oracle JDK.

We are pleased to recommend Tencent's OpenJDK distributions, namely Tencent Kona JDKs, which provide versions [8], [11] and [17]. They support Linux, macOS and Windows operating systems, and x86_64 and aarch64 CPUs.

### Android
By default, Tencent Kona SM Suite does not depend on any JDK internal API implementations, so it also can run on Android platform.

## Installation
All the artifacts (jar files) in Tencent Kona SM Suite are already uploaded to the [Maven Central] repository. Generally, it just needs to declare the artifacts as dependencies in the project build scripts. For example, a [Gradle] script can declare the dependencies as the below,

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

Note that, it is unnecessary to put all the providers into the classpath. Please declare the dependencies as you need. For example, if only need the ShangMi crypto algorithms and want to use provider `Kona`, the dependency declaration may look like the followings,

```
dependencies {
    implementation("com.tencent.kona:kona-crypto:<version>")
    implementation("com.tencent.kona:kona-provider:<version>")
}
```

## Build
Tencent Kona SM Suite uses Gradle to build this project. And the build script uses [Kotlin DSL]. This Gradle project contains four subprojects, namely *kona-crypto*，*kona-pkix*，*kona-ssl* and *kona-provider*. They respectively correspond to the four providers, namely `KonaCrypto`，`KonaPKIX`，`KonaSSL` and `Kona`.

A typical way to build this project just usts the following command:

```
gradle build
```

It will compile the source codes, execute unit tests and finally make the jar files. It also can just build a subproject, like the below,

```
gradle :kona-pkix:build
```

## Contributing
Welcome to evolve and maintain Tencent Kona SM Suite with us together. Please read [CONTRIBUTING.md] for the details on reporting bugs, reporting security vulnerabilities, raising requirements and contributing codes.

## License
Tencent Kona SM Suite is licensed under GNU GPL v2.0 license with classpath exception. For more details, please read the attached license [text].

## FAQ
Q: Why may SM2 Cipher throw exception `java.security.InvalidKeyException: Illegal key size or default parameters`?<br>
A: Before JDK `8u161`, JDKs don't support stronger algorithm and longer key length by default. These JDKs don't support 256-bit key, like `AES-256`. SM2 encryption algorithm just needs 256-bit keys, so it is also affected by this limit. For the solution details, please refer to this [Stack Overflow question].

Q: Can support `ECC_SM4_GCM_SM3` and `ECDHE_SM4_GCM_SM3` in TLS 1.2?<br>
A: There is no any RFC specification introducing these cipher suites to TLS 1.2, so it cannot support them in this protocol. However, this project supports `TLS_SM4_GCM_SM3` in TLS 1.3 based on RFC 8998.

Q: Is `GMSSL` or `GMSSL 1.1` supported?<br>
A: China's specification GB/T 38636-2020 defined the TLS-liked protocol as `Transport layer cryptography protocol`, so the protocol name in this project is`TLCP`, and the version is `1.1`. Certainly, `TLCP` or `TLCP 1.1` is `GMSSL` or`GMSSL 1.1`.

Q: Why cannot run the tests in this project with Oracle JDK?<br>
A: Oracle JDK requires a JCE implementation (here is `KoneCrypto`) must be signed and the associated certificate must be issued by Oracle JCE Code Signing CA. When directly executing the tests with the project source, `KonaCrypto` Provider is not signed yet, so they cannot run on Oracle JDK. But note that, the artifacts in Maven Central repository are already signed and surely can run on Oracle JDK.

Q: Is this project related to BouncyCastle?<br>
A: The earlier versions of this project used the SM algorithms from BouncyCastle, but since `1.0.5`, this project doesn't depend on BouncyCastle any more. In addition, please note BouncyCastle doesn't support SM protocols, including TLCP and TLS 1.3/RFC 8998.

Q: How old JDK 8 released can be supported<br>
A: Different scenarios require different JDK 8 releases. 1. Only need SM algorithms and/or TLCP protocol, this project can support `8u141` or older releases. 2. Requires ALPN extension with TLCP protocol, this oldest JDK 8 release is `8u251`. 3. In order to apply TLS 1.3/RFC 8998, `8u261` or higher is required.


[JCA]:
<https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html>

[KonaCrypto]:
<kona-crypto/README.md>

[KonaPKIX]:
<kona-pkix/README.md>

[KonaSSL]:
<kona-ssl/README.md>

[Kona]:
<kona-provider/README.md>

[kona-demo]:
<kona-demo/README.md>

[certificate]:
<https://www.oracle.com/java/technologies/javase/getcodesigningcertificate.html#jcacodesigning>

[8]:
<https://github.com/Tencent/TencentKona-8>

[11]:
<https://github.com/Tencent/TencentKona-11>

[17]:
<https://github.com/Tencent/TencentKona-17>

[Maven Central]:
<https://repo1.maven.org/maven2/com/tencent/kona/>

[Gradle]:
<https://gradle.org>

[Kotlin DSL]:
<https://docs.gradle.org/current/userguide/kotlin_dsl.html>

[CONTRIBUTING.md]:
<CONTRIBUTING.md>

[text]:
<LICENSE.txt>

[Stack Overflow question]:
<https://stackoverflow.com/questions/3862800/invalidkeyexception-illegal-key-size>
