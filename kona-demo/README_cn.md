**[English]** | 中文

# Tencent Kona Demo

## 简介
Tencent Kona Demo是一个基于Spring Boot的服务端应用，它仅用于展示如何将本套组件集成到Spring Boot工程中，它并不是本项目的制品之一。

`kona-demo`支持了两个内嵌的Web服务器，即`Jetty`和`Tomcat`。但只有Jetty Web服务器`JettyServer`是`SpringBootApplication`，可以由Gradle的`bootRun`任务启动。而Tomcat Web服务器`TomcatServer`是一个普通的应用程序。

## 使用
启动Jetty服务器，可以使用如下命令，

```
./gradlew :kona-demo:bootRun
```


[English]:
<README.md>
