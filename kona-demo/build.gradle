/*
 * Copyright (C) 2023, THL A29 Limited, a Tencent company. All rights reserved.
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
    alias(libs.plugins.springboot).apply(true)
    alias(libs.plugins.springdepman).apply(true)
}

dependencies {
    implementation(project(":kona-crypto"))
    implementation(project(":kona-pkix"))
    implementation(project(":kona-ssl"))
    implementation(project(":kona-provider"))

    implementation(libs.spring.boot.starter.web)
    implementation(libs.spring.boot.starter.tomcat)
    implementation(libs.spring.boot.starter.jetty)

    implementation(libs.tomcat.embed.core)
    implementation(libs.jetty.http2.server)
    if(JavaVersion.current().isJava8()) {
        implementation(libs.jetty.alpn.openjdk8.server)
    } else {
        implementation(libs.jetty.alpn.java.server)
    }
    implementation(libs.apache.httpclient)
}
