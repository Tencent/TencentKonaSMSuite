import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent

plugins {
    id("java-library")
    id("maven-publish")
}

group = "com.tencent.kona"
version = "1.0.1"

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8

    withSourcesJar()
    withJavadocJar()
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":kona-crypto"))
    implementation(project(":kona-pkix"))

    testImplementation("org.bouncycastle:bcprov-jdk18on:1.71")

    testImplementation("io.netty:netty-all:4.1.77.Final")
    testImplementation("org.eclipse.jetty:jetty-server:9.4.44.v20210927")
    testImplementation("org.eclipse.jetty:jetty-servlet:9.4.44.v20210927")
    testImplementation("org.eclipse.jetty:jetty-client:9.4.44.v20210927")
    testImplementation("org.apache.httpcomponents:httpclient:4.5.13")

    testRuntimeOnly("org.junit.jupiter:junit-jupiter:5.8.2")
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.8.2")

    testImplementation("org.openjdk.jmh:jmh-core:1.35")
    testAnnotationProcessor("org.openjdk.jmh:jmh-generator-annprocess:1.35")
}

tasks {
    compileJava {
        options.encoding = "UTF-8"
    }

    compileTestJava {
        options.encoding = "UTF-8"
    }

    test {
        useJUnitPlatform()

        filter {
            includeTestsMatching("*Test")
            includeTestsMatching("*Demo")

            val babasslPathProp = "test.babassl.path"
            val babasslPath = System.getProperty(babasslPathProp, "babassl")

            if (!isBabaSSLAvailable(babasslPath)) {
                // Ignore BabaSSL-related tests if no BabaSSL is available
                excludeTestsMatching("*BabaSSL*Test")
            } else {
                systemProperty(babasslPathProp, babasslPath)
            }
        }

        systemProperty("test.classpath", classpath.joinToString(separator = ":"))
        if (JavaVersion.current() == JavaVersion.VERSION_11) {
            jvmArgs("--add-exports", "java.base/jdk.internal.misc=ALL-UNNAMED")
        } else if (JavaVersion.current() == JavaVersion.VERSION_17) {
            jvmArgs("--add-exports", "java.base/jdk.internal.access=ALL-UNNAMED")
        }

        testLogging {
            events = mutableSetOf(
                TestLogEvent.PASSED,
                TestLogEvent.FAILED,
                TestLogEvent.SKIPPED
            )
            showStandardStreams = true
            showExceptions = true
            exceptionFormat = TestExceptionFormat.FULL
            showCauses = true
            showStackTraces = true

            addTestListener(object : TestListener {
                override fun beforeSuite(suite: TestDescriptor?) { }

                override fun afterSuite(
                        descriptor: TestDescriptor, result: TestResult) {
                    if (descriptor.parent == null) {
                        println("Test summary: " +
                                "Passed: ${result.successfulTestCount}, " +
                                "Failed: ${result.failedTestCount}, " +
                                "Skipped: ${result.skippedTestCount}")
                    }
                }

                override fun beforeTest(testDescriptor: TestDescriptor?) { }

                override fun afterTest(
                        descriptor: TestDescriptor?, result: TestResult?) { }
            })
        }
    }

    javadoc {
        options.locale = "en_US"
        isFailOnError = false
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])

            pom {
                name.set("Tencent Kona SSL Provider")
                description.set("A Java security provider for supporting protocols TLCP, TLS 1.3 (RFC 8998) and TLS 1.2")
                url.set("https://github.com/Tencent/TencentKonaSMSuite/tree/master/kona-ssl")
                licenses {
                    license {
                        name.set("GNU GPL v2.0 license with classpath exception")
                        url.set("https://github.com/Tencent/TencentKonaSMSuite/blob/master/LICENSE.txt")
                    }
                }
            }
        }
    }
}

// Determine if BabaSSL is available
fun isBabaSSLAvailable(babasslPath: String): Boolean {
    var exitCode : Int = -1
    try {
        val process = ProcessBuilder()
            .command(babasslPath, "version")
            .start()
        process.waitFor(3, TimeUnit.SECONDS)
        exitCode = process.exitValue()
    } catch (e: Exception) {
        println("BabaSSL is unavailable: " + e.cause)
    }

    return exitCode == 0
}
