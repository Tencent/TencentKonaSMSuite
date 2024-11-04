English | **[中文]**

# Tencent Kona Provider

## Introduction
Tencent Kona Provider wraps all the features in `KonaCrypto`，`KonaPKIX` and `KonaSSL` providers into a single provider，so that the applications can just use a single provider name, exactly `Kona`, to invoke all the features in those three providers。

## Usages
The provider `Kona` just wraps the providers `KonaCrypto`，`KonaPKIX` and `KonaSSL`, then please reference theirs READMEs for the usages.

### Loading
Before using any feature in `Kona`, it has to load `KonaProvider`,

```
Security.addProvider(new KonaProvider());
```

The above line adds the provider to the last position of the provider list. If necessary, it also can insert the provider at a specific position, like the below,

```
Security.insertProviderAt(new KonaProvider(), position);
```

the less the position value is, the higher the privilege is. The minimum value is 1. However, it's not recommended to prioritize this provider. So, `Security.addProvider` is recommended.

Please note that is no need to load `KonaCryptoProvider`，`KonaPKIXProvider` or `KonaSSLProvider`. Instead, it just needs to put their jars into the classpath. `Kona` can load all the features in these three providers via reflection.


[中文]:
<README_cn.md>
