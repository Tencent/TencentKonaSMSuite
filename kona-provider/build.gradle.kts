plugins {
    id("kona-common")
}

dependencies {
    testImplementation(project(":kona-crypto"))
    testImplementation(project(":kona-pkix"))
    testImplementation(project(":kona-ssl"))

    testImplementation(libs.netty.all)
    testImplementation(libs.jetty.server)
    testImplementation(libs.jetty.servlet)
    testImplementation(libs.jetty.client)
    testImplementation(libs.apache.httpclient)

    testImplementation(libs.junit.jupiter.api)
    testRuntimeOnly(libs.junit.jupiter.engine)
}
