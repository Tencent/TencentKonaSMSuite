English | **[中文]**

# Contributing

Welcome to contribute Tencent Kona SM Suite in a variety of ways. Before start to contribute, please read the following suggestions.

## Report issues
Using Tencent Kona SM Suite is a great contribution. And it is greater that you can report any problem when you use this suite. Please report your problems in the project [Issues]. Please indicate the version, the JDK versions and the operating systems. It would be better to provider the test codes for reproducing the problems.

## Report security vulnerabilities
Tencent Kona SM Suite is a security component, we seriously focus on its security. If you find a possible security issue or vulnerability, please DON'T report it to [Issues] in public. Instead, please directly send the report to the mail address `johnsjiang at tencent.com`. It's highly recommended that encrypting the content of the report with the below [PGP] public key.

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

## Raise requirements
Tencent Kona SM Suite complies to China's ShangMi-associated specifications and is based on JDK's standard Service Provider Interface (SPI). If you think this component doesn't adapt to some specific scenarios, or the designs have flaws, please also raise them to [Issues].

## Contribute codes
Before contribute any code to this project, please know that it is [licensed] under GNU GPL v2.0 license with classpath exception. Please request code integration via GitHub [Pull Request]. Please focus on the code quality. You can refer to Oracle's [Java coding convention]. Please add [JUnit 5] tests for fixing bugs or developing features. Developing only unit tests are also welcomed. More unit tests are really beneficial for the project quality. They will help for future possible refactoring. The test codes are as important as product codes.

**Thanks for your help in advance!**


[中文]:
<CONTRIBUTING_cn.md>

[PGP]:
<https://en.wikipedia.org/wiki/Pretty_Good_Privacy>

[Issues]:
<https://github.com/tencent/TencentKonaSMSuite/issues>

[licensed]:
<LICENSE.txt>

[Pull Request]:
<https://docs.github.com/en/pull-requests>

[Java coding convention]:
<https://www.oracle.com/java/technologies/javase/codeconventions-introduction.html>

[JUnit 5]:
<https://junit.org/junit5>
