plugins {
    id("kona-common")
}

dependencies {
    implementation(project(":kona-crypto"))
    implementation(project(":kona-pkix"))

    testImplementation("io.netty:netty-all:4.1.77.Final")
    testImplementation("org.eclipse.jetty:jetty-server:9.4.44.v20210927")
    testImplementation("org.eclipse.jetty:jetty-servlet:9.4.44.v20210927")
    testImplementation("org.eclipse.jetty:jetty-client:9.4.44.v20210927")
    testImplementation("org.apache.tomcat.embed:tomcat-embed-core:9.0.78")
    testImplementation("org.apache.httpcomponents:httpclient:4.5.13")
    testImplementation("com.squareup.okhttp3:okhttp:4.11.0")

    jmhImplementation("org.openjdk.jmh:jmh-core:1.35")
    jmhAnnotationProcessor("org.openjdk.jmh:jmh-generator-annprocess:1.35")
    jmhImplementation(sourceSets["test"].runtimeClasspath)
}
