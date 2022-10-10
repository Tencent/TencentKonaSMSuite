# 作出贡献

非常欢迎以不同的方式向腾讯Kona国密套件作出贡献。在您开始之前请先阅读下面的内容。

## 报告缺陷
使用腾讯Kona国密套件就是对它的一种贡献，如果能报告遇到的问题则更令人欣喜。请在本项目的[Issues]中提交您遇到的问题。请注明所使用的版本，JDK版本和操作系统平台，最好能提供复现问题的测试程序。

## 报告安全漏洞
腾讯Kona国密套件作为安全领域的基础组件，其安全性始终是我们高度关注的焦点。如果您遇到了可能的安全漏洞，请不要公开地报告到[Issues]中，而是将它直接发送到邮箱地址`johnsjiang at tencent.com`。非常推荐使用下面的[PGP]公钥对报告的内容进行加密。

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEYyk2IRYJKwYBBAHaRw8BAQdAViRaG71X7PJQP+AUf/D8l+kQ6e6az3e9RdoX
b/8kcvy0P0pvaG4gSmlhbmcgKEpvaG4gSmlhbmcncyB3b3JraW5nIG1haWwpIDxq
b2huc2ppYW5nQHRlbmNlbnQuY29tPoiUBBMWCgA8FiEEbeJu+uFKMgK12O23c98H
pz3L6mMFAmMpNiECGwMFCwkIBwIDIgIBBhUKCQgLAgQWAgMBAh4HAheAAAoJEHPf
B6c9y+pjv8kBAKcemNLgDIok8mF2XE7PG0wNS7zBxXKHFCAd1GvRnhoUAQC2eQF7
sk8eZghA8iX0CKYZv6wlL7/LtT8HSTzCkYHgALg4BGMpNiESCisGAQQBl1UBBQEB
B0C2pzM8kBHttj1xRLDcalxKJVbk9xurZYctnQjLgpzzbgMBCAeIeAQYFgoAIBYh
BG3ibvrhSjICtdjtt3PfB6c9y+pjBQJjKTYhAhsMAAoJEHPfB6c9y+pjy9oBALZJ
1kvYwMgMzjkThFsYaNbWpvovDcuRckpNEnaxPiU1AP9RU8UCHPxIY1dtTFkySoWg
o9MYV6zBTB5FONtVo9w/BA==
=zYuj
-----END PGP PUBLIC KEY BLOCK-----
```

## 提出需求
腾讯Kona国密套件遵循相关的中国国家标准，并基于OpenJDK的标准Service Provider Interface（SPI），实现了国密的基础算法和安全通信协议。在此基础上，如果您发现它不适用于某些特定场景，或程序设计上存在可能的改进之处，请在[Issues]中提出你的需求或建议。

## 贡献代码
在向腾讯Kona国密套件贡献代码之前，需要了解到它使用GNU GPL v2.0 license with classpath exception[许可协议]。通过GitHub的[Pull Request]向本项目提出合并代码的请求。请关注代码的质量，可以参考Oracle的[Java编码规范]。在修复缺陷或增加特性时，请务必提供相应的基于[JUnit 5]的单元测试程序。我们也非常欢迎为本项目增加新的单元测试。更多的测试用例不仅有利于确保本项目的质量，也将会帮助未来可能的重构。测试代码的价值并不亚于产品代码本身。

**在此先感谢您的帮助！**

[PGP]:
<https://en.wikipedia.org/wiki/Pretty_Good_Privacy>

[Issues]:
<https://github.com/tencent/TencentKonaSMSuite/issues>

[许可协议]:
<LICENSE.txt>

[Pull Request]:
<https://docs.github.com/en/pull-requests>

[Java编码规范]:
<https://www.oracle.com/java/technologies/javase/codeconventions-introduction.html>

[JUnit 5]:
<https://junit.org/junit5>
