/*
 * Copyright (C) 2023, 2024, THL A29 Limited, a Tencent company. All rights reserved.
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

import org.apache.tools.ant.taskdefs.condition.Os
import org.gradle.api.tasks.testing.Test
import org.gradle.api.tasks.testing.TestDescriptor
import org.gradle.api.tasks.testing.TestListener
import org.gradle.api.tasks.testing.TestResult
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent
import java.util.concurrent.TimeUnit

abstract class CommonTest : Test() {
    init {
        useJUnitPlatform()

        filter {
            includeTestsMatching("*Test")
            includeTestsMatching("*Demo")

            // Ignore the tests depending local paths on Windows
            if (Os.isFamily(Os.FAMILY_WINDOWS)) {
                excludeTestsMatching("com.tencent.kona.pkix.tool.*")
                excludeTestsMatching("com.tencent.kona.ssl.hybrid.*")
                excludeTestsMatching("com.tencent.kona.ssl.tlcp.*")
                excludeTestsMatching("com.tencent.kona.ssl.tls.*")
                excludeTestsMatching("com.tencent.kona.ssl.misc.*")
            }

            val tongsuoPathProp = "test.tongsuo.path"
            val tongsuoPath = System.getProperty(tongsuoPathProp, "tongsuo")

            if (!isTongsuoAvailable(tongsuoPath)) {
                // Ignore Tongsuo-related tests if no Tongsuo is available
                excludeTestsMatching("*Tongsuo*Test")
            } else {
                systemProperty(tongsuoPathProp, tongsuoPath)
            }
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
}

// Determine if Tongsuo is available
fun isTongsuoAvailable(tongsuoPath : String): Boolean {
    var exitCode : Int = -1
    try {
        val process = ProcessBuilder()
            .command(tongsuoPath, "version")
            .start()
        process.waitFor(3, TimeUnit.SECONDS)
        exitCode = process.exitValue()

        val versionInfo = process.getInputStream().bufferedReader().use {
            it.readText()
        }
        System.out.print(versionInfo)
    } catch (e: Exception) {
        println("Tongsuo is unavailable: " + e.cause)
    }

    return exitCode == 0
}
