plugins {
    id("kona-common")
}

dependencies {
    implementation(project(":kona-crypto"))
    implementation(project(":kona-pkix"))

    testImplementation(libs.netty.all)
    testImplementation(libs.tomcat.embed.core)
    testImplementation(libs.jetty.server)
    testImplementation(libs.jetty.servlet)
    testImplementation(libs.jetty.client)
    testImplementation(libs.apache.httpclient)
    testImplementation(libs.okhttp)

    testImplementation(libs.junit.jupiter.api)
    testRuntimeOnly(libs.junit.jupiter.engine)
    testRuntimeOnly(libs.junit.platform.launcher)

    jmhImplementation(libs.jmh.core)
    jmhImplementation(libs.jmh.generator.annprocess)
    jmhImplementation(sourceSets["test"].runtimeClasspath)
}
