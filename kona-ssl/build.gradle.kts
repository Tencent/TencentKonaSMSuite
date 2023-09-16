/*
 * Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
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
