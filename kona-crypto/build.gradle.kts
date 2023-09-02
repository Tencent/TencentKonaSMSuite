plugins {
    id("kona-common")
}

dependencies {
    testImplementation(libs.bcprov.jdk18on)

    testImplementation(libs.junit.jupiter.api)
    testRuntimeOnly(libs.junit.jupiter.engine)

    jmhImplementation(libs.jmh.core)
    jmhAnnotationProcessor(libs.jmh.generator.annprocess)
    jmhImplementation(sourceSets["test"].runtimeClasspath)
}
