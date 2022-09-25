import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent

plugins {
    id("kona-common")
}

dependencies {
    implementation(project(":kona-crypto"))
}
