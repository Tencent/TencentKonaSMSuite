/*
 * Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
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

package com.tencent.kona.jdk.internal.misc;

import static com.tencent.kona.crypto.CryptoUtils.*;

import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.EncodedKeySpec;

/**
 * The utilities for operating SharedSecrets cross JDK 8, 11 and 17.
 */
public class SharedSecretsUtil {

    // Use SharedSecrets by default on JDK 8
    private static final boolean USE_SHARED_SECRETS
            = privilegedGetBoolProperty("com.tencent.misc.useSharedSecrets",
                    isJdk8() ? "true" : "false");

    /* JavaLangAccess */
    private static final Method langNewStringNoRepl;
    private static final Method initialSystemIn;
    private static final Object langAccess;

    /* JavaIOAccess */
    private static final Method console;
    private static final Method charset;
    private static final Object ioAccess;

    /* JavaxCryptoSpecAccess */
    private static final Method cryptoSpecClearSecretKeySpec;
    private static final Object cryptoSpecAccess;

    /* JavaNetInetAddressAccess */
    private static final Method netInetAddressGetOriginalHostName;
    private static final Object netInetAddressAccess;

    /* JavaSecuritySignatureAccess */
    private static final Method secSignatureInitVerifyWithPubKey;
    private static final Method secSignatureInitVerifyWithCert;
    private static final Method secSignatureInitSign;
    private static final Object secSignatureAccess;

    /* JavaSecuritySpecAccess */
    private static final Method secSpecClearEncodedKeySpec;
    private static final Object secSpecAccess;

    static {
        Class<?> sharedSecretsClass = null;

        Class<?> javaLangAccessClass = null;
        Class<?> javaIOAccessClass = null;
        Class<?> javaxCryptoSpecAccessClass = null;
        Class<?> inetAddressAccessClass = null;
        Class<?> secSignatureAccessClass = null;
        Class<?> secSpecAccessClass = null;

        if (useSharedSecrets()) {
            try {
                if (isJdk8()) {
                    sharedSecretsClass = Class.forName("sun.misc.SharedSecrets");

                    javaLangAccessClass = Class.forName("sun.misc.JavaLangAccess");
                    javaIOAccessClass = Class.forName("sun.misc.JavaIOAccess");
                    inetAddressAccessClass = Class.forName("sun.misc.JavaNetAccess");
                    secSignatureAccessClass = Class.forName("sun.misc.JavaSecuritySignatureAccess");
                } else if (isJdk11()) {
                    sharedSecretsClass = Class.forName("jdk.internal.misc.SharedSecrets");

                    javaLangAccessClass = Class.forName("jdk.internal.misc.JavaLangAccess");
                    javaIOAccessClass = Class.forName("jdk.internal.misc.JavaIOAccess");
                    inetAddressAccessClass = Class.forName("jdk.internal.misc.JavaNetInetAddressAccess");
                    secSignatureAccessClass = Class.forName("jdk.internal.misc.JavaSecuritySignatureAccess");
                } else if (isJdk17()) {
                    sharedSecretsClass = Class.forName("jdk.internal.access.SharedSecrets");

                    javaLangAccessClass = Class.forName("jdk.internal.access.JavaLangAccess");
                    javaIOAccessClass = Class.forName("jdk.internal.access.JavaIOAccess");
                    javaxCryptoSpecAccessClass = Class.forName("jdk.internal.access.JavaxCryptoSpecAccess");
                    inetAddressAccessClass = Class.forName("jdk.internal.access.JavaNetInetAddressAccess");
                    secSignatureAccessClass = Class.forName("jdk.internal.access.JavaSecuritySignatureAccess");
                    secSpecAccessClass = Class.forName("jdk.internal.access.JavaSecuritySpecAccess");
                }
            } catch (ClassNotFoundException e) {
                throw new InternalError("Cannot get SharedSecrets class", e);
            }
        }

        if (sharedSecretsClass != null) {
            try {
                langNewStringNoRepl = isJdk8()
                        ? null : javaLangAccessClass.getMethod(
                                "newStringNoRepl", byte[].class, Charset.class);
                initialSystemIn = isJdk8()
                        ? null : javaLangAccessClass.getMethod("initialSystemIn");

                console = javaIOAccessClass.getMethod("console");
                charset = javaIOAccessClass.getMethod("charset");

                cryptoSpecClearSecretKeySpec = javaxCryptoSpecAccessClass != null
                        ? javaxCryptoSpecAccessClass.getMethod(
                                "clearSecretKeySpec", SecretKeySpec.class)
                        : null;

                netInetAddressGetOriginalHostName = inetAddressAccessClass.getMethod(
                        "getOriginalHostName", InetAddress.class);

                secSignatureInitVerifyWithPubKey = secSignatureAccessClass.getMethod(
                        "initVerify", Signature.class, PublicKey.class,
                        AlgorithmParameterSpec.class);
                secSignatureInitVerifyWithCert = secSignatureAccessClass.getMethod(
                        "initVerify", Signature.class, Certificate.class,
                        AlgorithmParameterSpec.class);
                secSignatureInitSign = secSignatureAccessClass.getMethod(
                        "initSign", Signature.class, PrivateKey.class,
                        AlgorithmParameterSpec.class, SecureRandom.class);

                secSpecClearEncodedKeySpec = secSpecAccessClass == null
                        ? null : secSpecAccessClass.getMethod(
                                "clearEncodedKeySpec", EncodedKeySpec.class);
            } catch (NoSuchMethodException e) {
                throw new InternalError("Cannot get method", e);
            }

            langAccess = getAccessObject(sharedSecretsClass, "getJavaLangAccess");
            ioAccess = getAccessObject(sharedSecretsClass, "getJavaIOAccess");
            cryptoSpecAccess = isJdk17()
                    ? getAccessObject(sharedSecretsClass, "getJavaxCryptoSpecAccess")
                    : null;
            netInetAddressAccess = isJdk8()
                    ? getAccessObject(sharedSecretsClass, "getJavaNetAccess")
                    : getAccessObject(sharedSecretsClass, "getJavaNetInetAddressAccess");
            secSignatureAccess = getAccessObject(sharedSecretsClass, "getJavaSecuritySignatureAccess");
            secSpecAccess = isJdk17()
                    ? getAccessObject(sharedSecretsClass, "getJavaSecuritySpecAccess")
                    : null;
        } else {
            langNewStringNoRepl = null;
            initialSystemIn = null;
            langAccess = null;

            console = null;
            charset = null;
            ioAccess = null;

            cryptoSpecClearSecretKeySpec = null;
            cryptoSpecAccess = null;

            netInetAddressGetOriginalHostName = null;
            netInetAddressAccess = null;

            secSignatureInitVerifyWithPubKey = null;
            secSignatureInitVerifyWithCert = null;
            secSignatureInitSign = null;
            secSignatureAccess = null;

            secSpecClearEncodedKeySpec = null;
            secSpecAccess = null;
        }
    }

    private static boolean useSharedSecrets() {
        return USE_SHARED_SECRETS && !isAndroid();
    }

    /* JavaLangAccess Start */
    public static String langNewStringNoRepl(byte[] bytes, Charset cs)
            throws CharacterCodingException {
        if (langNewStringNoRepl == null) {
            return new String(bytes, cs);
        }

        try {
            return (String) langNewStringNoRepl.invoke(
                    langAccess, bytes, cs);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException("getOriginalHostName failed", e);
        }
    }

    public static InputStream initialSystemIn() {
        if (initialSystemIn == null) {
            return System.in;
        }

        try {
            return (InputStream) initialSystemIn.invoke(langAccess);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException("initialSystemIn failed", e);
        }
    }
    /* JavaLangAccess End */

    /* JavaIOAccess Start */
    public static Console console() {
        if (console == null) {
            return null;
        }

        try {
            return (Console) console.invoke(ioAccess);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException("console failed", e);
        }
    }

    public static Charset charset() {
        if (charset == null) {
            return null;
        }

        try {
            return (Charset) charset.invoke(ioAccess);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException("charset failed", e);
        }
    }
    /* JavaIOAccess End */

    /* JavaxCryptoSpecAccess Start */
    public static void cryptoSpecClearSecretKeySpec(SecretKeySpec keySpec) {
        if (cryptoSpecClearSecretKeySpec == null) {
            return;
        }

        try {
            cryptoSpecClearSecretKeySpec.invoke(cryptoSpecAccess, keySpec);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException("specAccessClearEncodedKeySpec failed", e);
        }
    }
    /* JavaxCryptoSpecAccess End */

    /* JavaNetInetAddressAccess Start */
    public static String netInetAddressGetOriginalHostName(
            InetAddress inetAddress) {
        if (netInetAddressGetOriginalHostName == null) {
            return inetAddress.getHostName();
        }

        try {
            return (String) netInetAddressGetOriginalHostName.invoke(
                    netInetAddressAccess, inetAddress);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException("getOriginalHostName failed", e);
        }
    }
    /* JavaNetInetAddressAccess End */

    /* JavaSecuritySignatureAccess Start */
    public static void secSignatureInitVerify(Signature signature,
            PublicKey publicKey, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (secSignatureInitVerifyWithPubKey == null) {
            if (params != null) {
                signature.setParameter(params);
            }
            signature.initVerify(publicKey);
        } else {
            try {
                secSignatureInitVerifyWithPubKey.invoke(
                        secSignatureAccess, signature, publicKey, params);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new RuntimeException("signatureAccessInitVerify failed", e);
            }
        }
    }

    public static void secSignatureInitVerify(Signature signature,
            Certificate certificate, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (secSignatureInitVerifyWithCert == null) {
            if (params != null) {
                signature.setParameter(params);
            }
            signature.initVerify(certificate);
        } else {
            try {
                secSignatureInitVerifyWithCert.invoke(
                        secSignatureAccess, signature, certificate, params);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new RuntimeException("signatureAccessInitVerify failed", e);
            }
        }
    }

    public static void secSignatureInitSign(Signature signature,
            PrivateKey privateKey, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (secSignatureInitSign == null) {
            if (params != null) {
                signature.setParameter(params);
            }
            signature.initSign(privateKey, random);
        } else {
            try {
                secSignatureInitSign.invoke(
                        secSignatureAccess, signature, privateKey, params, random);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new RuntimeException("signatureAccessInitSign failed", e);
            }
        }
    }
    /* JavaSecuritySignatureAccess End */

    /* JavaSecuritySpecAccess Start */
    public static void secSpecClearEncodedKeySpec(EncodedKeySpec keySpec) {
        if (secSpecClearEncodedKeySpec == null) {
            return;
        }

        try {
            secSpecClearEncodedKeySpec.invoke(secSpecAccess, keySpec);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException("specAccessClearEncodedKeySpec failed", e);
        }
    }
    /* JavaSecuritySpecAccess End */

    private static Object getAccessObject(Class<?> sharedSecretsClass,
            String sharedSecretedMethodName) {
        try {
            Method sharedSecretedMethod = sharedSecretsClass.getDeclaredMethod(
                    sharedSecretedMethodName);
            sharedSecretedMethod.setAccessible(true);
            return sharedSecretedMethod.invoke(null);
        } catch (IllegalAccessException | InvocationTargetException
                | NoSuchMethodException e) {
            throw new InternalError("Cannot get access object", e);
        }
    }
}
