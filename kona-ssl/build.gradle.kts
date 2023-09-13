import com.google.protobuf.gradle.id

plugins {
    id("kona-common")
    alias(libs.plugins.protobuf).apply(true)
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

    testImplementation(libs.bundles.grpc)

    testImplementation(libs.junit.jupiter.api)
    testRuntimeOnly(libs.junit.jupiter.engine)
    testRuntimeOnly(libs.junit.platform.launcher)

    jmhImplementation(libs.jmh.core)
    jmhImplementation(libs.jmh.generator.annprocess)
    jmhImplementation(sourceSets["test"].runtimeClasspath)
}

protobuf {
    protoc {
        artifact = libs.protoc.get().toString()
    }

    plugins {
        id("grpc") {
            artifact = libs.grpc.protoc.gen.grpc.get().toString()
        }
    }

    generateProtoTasks {
         all().forEach {
            it.plugins {
                id("grpc")
            }
        }
    }
}
