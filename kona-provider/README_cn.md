**[English]** | 中文

# 腾讯Kona Provider

## 简介
腾讯Kona Provider是将`KonaCrypto`，`KonaPKIX`和`KonaSSL`中的全部特性封装到单个Provider中，以方便应用程序仅使用一个统一的Provider名称，即`Kona`，去调用前面三个组件中的所有特性。

## 使用
由于`Kona`只是对`KonaCrypto`，`KonaPKIX`和`KonaSSL`的封装，各个特性的具体使用方法请分别参考那三个组件各自的README。

### 加载
在使用`Kona`中的任何特性之前，必须要加载`KonaProvider`，

```
Security.addProvider(new KonaProvider());
```

上面的方法会将这个Provider加到整个Provider列表的最后一位，其优先级则为最低。如有必要，可以使用下面的方法将它们插入到Provider列表的指定位置，

```
Security.insertProviderAt(new KonaProvider(), position);
```

position的值越小，代表的优先级越高，最小可为1。

注意：在使用`Kona`时，并不需要加载`KonaCryptoProvider`，`KonaPKIXProvider`或`KonaSSLProvider`，而只需要将它们的jar文件放入类路径中。`Kona`会通过反射自动地加载这三个Provider的特性。


[English]:
<README.md>
