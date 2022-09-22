import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent

plugins {
    id("java-library")
    id("maven-publish")
    id("signing")
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

    testImplementation("org.bouncycastle:bcprov-jdk18on:1.71")

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
        }

        systemProperty("test.classpath", classpath.joinToString(separator = ":"))
        if(JavaVersion.current() == JavaVersion.VERSION_11) {
            jvmArgs("--add-exports", "java.base/jdk.internal.misc=ALL-UNNAMED")
        } else if(JavaVersion.current() == JavaVersion.VERSION_17) {
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
                name.set("Tencent Kona PKIX Provider")
                description.set("A Java security provider for supporting ShangMi algorithms in public key infrastructure")
                url.set("https://github.com/Tencent/TencentKonaSMSuite/tree/master/kona-pkix")
                licenses {
                    license {
                        name.set("GNU GPL v2.0 license with classpath exception")
                        url.set("https://github.com/Tencent/TencentKonaSMSuite/blob/master/LICENSE.txt")
                    }
                }
            }
        }
    }

    repositories {
        maven {
            val snapshotRepoURL = uri("https://oss.sonatype.org/content/repositories/snapshots")
            val releaseRepoURL = uri("https://oss.sonatype.org/service/local/staging/deploy/maven2")
            url = if (version.toString().endsWith("-SNAPSHOT")) snapshotRepoURL else releaseRepoURL

            // gradle.properties contains the below properties:
            // ossrhUsername=<OSSRH User Name>
            // ossrhPassword=<OSSRH Password>
            name = "ossrh"
            credentials(PasswordCredentials::class)
        }
    }
}

signing {
    sign(publishing.publications["maven"])
}
