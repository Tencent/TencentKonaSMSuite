plugins {
    id("kona-common")
}

dependencies {
    jmhImplementation("org.openjdk.jmh:jmh-core:1.35")
    jmhAnnotationProcessor("org.openjdk.jmh:jmh-generator-annprocess:1.35")
    jmhImplementation(sourceSets["test"].runtimeClasspath)
}
