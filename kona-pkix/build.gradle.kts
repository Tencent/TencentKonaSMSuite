plugins {
    id("kona-common")
}

dependencies {
    implementation(project(":kona-crypto"))

    testImplementation(libs.junit.jupiter.api)
    testRuntimeOnly(libs.junit.jupiter.engine)
    testRuntimeOnly(libs.junit.platform.launcher)
}
