import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent

plugins {
    id("kona-common")
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.71")
}
