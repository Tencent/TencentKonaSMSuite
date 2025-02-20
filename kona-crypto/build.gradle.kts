/*
 * Copyright (C) 2022, 2025, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

plugins {
    id("kona-common")
}

dependencies {
    testImplementation(libs.bcprov.jdk18on)

    testImplementation(libs.junit.jupiter.api)
    testRuntimeOnly(libs.junit.jupiter.engine)
    testRuntimeOnly(libs.junit.platform.launcher)

    jmhImplementation(libs.jmh.core)
    jmhAnnotationProcessor(libs.jmh.generator.annprocess)
    jmhImplementation(sourceSets["test"].runtimeClasspath)
}

tasks.register<Exec>("genJNIHeaders") {
    dependsOn("compileJava")

    val konaIncludeDir = file("src/main/jni/include/kona").absolutePath
    if (JavaVersion.current() == JavaVersion.VERSION_1_8) {
        commandLine = listOf(
            "javah",
            "-classpath", sourceSets["main"].runtimeClasspath.asPath,
            "-d", konaIncludeDir,
            "com.tencent.kona.crypto.provider.nativeImpl.NativeCrypto"
        )
    } else {
        commandLine = listOf(
            "javac",
            "-classpath", sourceSets["main"].runtimeClasspath.asPath,
            "-h", konaIncludeDir,
            "-d", konaIncludeDir,
            file("src/main/java/com/tencent/kona/crypto/provider/nativeImpl/NativeCrypto.java").absolutePath
        )
    }
}
