/*
 * Copyright (C) 2025, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. THL A29 Limited designates
 * this particular file as subject to the "Classpath" exception as provided
 * in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package com.tencent.kona;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Locale;
import java.util.regex.Pattern;

public class KonaUtils {

    private static final String OS = privilegedGetProperty("os.name");
    private static final String ARCH = privilegedGetProperty("os.arch");

    private static final String JDK_VERSION = privilegedGetProperty(
            "java.specification.version");

    private static final String JDK_VENDOR = privilegedGetProperty(
            "java.specification.vendor");

    // Java, Native or NativeOneShot
    private static final String DEFAULT_CRYPTO = privilegedGetProperty(
            "com.tencent.kona.defaultCrypto", "Java");

    public static String privilegedGetProperty(String key, String def) {
        return AccessController.doPrivileged(
                (PrivilegedAction<String>) () -> System.getProperty(key, def));
    }

    public static String privilegedGetProperty(String key) {
        return privilegedGetProperty(key, null);
    }

    public static Boolean privilegedGetBoolProperty(String key, String def) {
        return AccessController.doPrivileged(
                (PrivilegedAction<Boolean>) () -> Boolean.parseBoolean(
                        System.getProperty(key, def)));
    }

    public static Boolean privilegedGetBoolProperty(String key) {
        return privilegedGetBoolProperty(key, "false");
    }

    public static boolean isJdk8() {
        return JDK_VERSION.equals("1.8");
    }

    public static boolean isJdk11() {
        return JDK_VERSION.equals("11");
    }

    public static boolean isJdk17() {
        return JDK_VERSION.equals("17");
    }

    public static boolean isJdk21() {
        return JDK_VERSION.equals("21");
    }

    public static boolean isAndroid() {
        return JDK_VENDOR.contains("Android");
    }

    public static String defaultCrypto() {
        return isLinux() && !isAndroid() ? DEFAULT_CRYPTO : "Java";
    }

    public static boolean isLinux() {
        return isOs("linux");
    }

    public static boolean isMac() {
        return isOs("mac");
    }

    private static boolean isOs(String osname) {
        return OS.toLowerCase(Locale.ENGLISH).startsWith(
                osname.toLowerCase(Locale.ENGLISH));
    }

    public static boolean isX64() {
        return isArch("(amd64)|(x86_64)");
    }

    public static boolean isArm64() {
        return isArch("aarch64");
    }

    private static boolean isArch(String arch) {
        return Pattern.compile(arch, Pattern.CASE_INSENSITIVE)
                .matcher(ARCH)
                .matches();
    }
}
