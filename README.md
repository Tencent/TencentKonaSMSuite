# Tencent Kona SM Suite

## Overview

Tencent Kona SM Suite is a set of Java security providers, which service the ShangMi applications in Java ecosystem. This suite contains four providers:

- [KonaCrypto]，which implements SM2, SM3 and SM4 algorithms based on Java Cryptography Architecture.
- [KonaPKIX]，which supports ShangMi algorithms on loading certificate and certificate chain verification. It also can load and write key store files containing ShangMi certificates.
- [KonaSSL] implements China's Transport Layer Cryptographic Protocol, and also applies ShangMi algorithms to TLS 1.3 based on RFC 8998.
- [Kona], which wraps all the features in `KonaCrypto`，`KonaPKIX` and `KonaSSL`. Generally, it recommends users to use this provider.

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
    implementation("com.tencent.kona:kona-crypto:1.0.7.1")
    implementation("com.tencent.kona:kona-pkix:1.0.7.1")
    implementation("com.tencent.kona:kona-ssl:1.0.7.1")
    implementation("com.tencent.kona:kona-provider:1.0.7.1")
}
```

Note that, it is unnecessary to put all the providers into the classpath. Please declare the dependencies as you need. For example, if only need the ShangMi crypto algorithms and want to use provider `Kona`, the dependency declaration may look like the followings,

```
dependencies {
    implementation("com.tencent.kona:kona-crypto:1.0.7")
    implementation("com.tencent.kona:kona-provider:1.0.7")
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
