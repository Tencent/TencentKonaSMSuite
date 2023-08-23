English | **[中文]**

# Tencent Kona Demo

## Introduction
Tencent Kona Demo is a server-side application based on Spring Boot. It is only used for demonstrating the approach on integrating this suite to a Spring Boot project. However, this module is not one of the artifacts of this project.

`kona-demo` supports two embedded web servers, including Jetty and Tomcat. But only Jetty web server `JettyServer` is a `SpringBootApplication`, so it can be launched by Gradle task `bootRun`. However, Tomcat web server `TomcatServer` is a common application.

## Usages
It can launch the Jetty server via the below command,

```
./gradlew :kona-demo:bootRun
```


[中文]:
<README_cn.md>
