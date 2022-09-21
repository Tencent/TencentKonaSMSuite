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
    implementation("org.bouncycastle:bcprov-jdk18on:1.71")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.8.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.8.2")

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
        }

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
    publications.create<MavenPublication>("maven") {
        from(components["java"])
    }
}
