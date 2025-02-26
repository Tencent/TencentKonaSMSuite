/*
 * Copyright (C) 2024, 2025, THL A29 Limited, a Tencent company. All rights reserved.
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

package com.tencent.kona.crypto.provider.nativeImpl;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import static com.tencent.kona.crypto.CryptoUtils.*;

/**
 * The internal APIs for underlying native crypto library from OpenSSL.
 */
final class NativeCrypto {

    private static final String OPENSSL_CRYPTO_LIB = privilegedGetProperty(
            "com.tencent.kona.openssl.crypto.lib.path");
    private static final String KONA_CRYPTO_LIB = privilegedGetProperty(
            "com.tencent.kona.crypto.lib.path");

    static {
        loadLibs();
    }

    private static void loadLibs() {
        loadLib("OpenSSLCrypto", OPENSSL_CRYPTO_LIB);
        loadLib("KonaCrypto", KONA_CRYPTO_LIB);
    }

    private static void loadLib(String libName, String libPath) {
        if (libPath != null && !libPath.isEmpty()) {
            systemLoad(libPath);
        } else {
            loadLibFromJar(libName);
        }
    }

    private static void loadLibFromJar(String libName) {
        String libFileName = getNativeLibFileName(libName);
        if (libFileName == null) {
            throw new RuntimeException(libName + " lib is not found for this platform");
        }

        Path tempLibDir = null;
        try {
            tempLibDir = Files.createTempDirectory("TencentKona-" + libName);
            loadLibFromTempDir(tempLibDir, libFileName);
        } catch (Exception e) {
            throw new RuntimeException("Loaded lib failed: " + libName, e);
        } finally {
            if (tempLibDir != null) {
                try {
                    Files.walk(tempLibDir).map(Path::toFile).forEach(File::delete);
                    Files.deleteIfExists(tempLibDir);
                } catch (IOException e) {
                    System.out.println("Cannot delete temp native lib dir: "
                            + tempLibDir);
                    e.printStackTrace(System.out);
                }
            }
        }
    }

    private static void loadLibFromTempDir(Path tempLibDir, String libFileName)
            throws PrivilegedActionException {
        // Copy platform-specific native lib from jar to a temp local path
        String libFilePath = AccessController.doPrivileged((PrivilegedExceptionAction<String>) () -> {
            Path tempLibPath = tempLibDir.resolve(libFileName);
            copyNativeLib(libFileName, tempLibPath);

            return tempLibPath.toAbsolutePath().toString();
        });

        systemLoad(libFilePath);
    }

    private static void systemLoad(String libFilePath) {
        Path bufPath = Paths.get(libFilePath);
        if (!Files.exists(bufPath) || !Files.isRegularFile(bufPath)) {
            throw new RuntimeException("Lib file is not found: " + libFilePath);
        }

        System.load(libFilePath);
    }

    private static String getNativeLibFileName(String libName) {
        String platform = null;
        String ext = null;

        if (isX64()) {
            if (isMac()) {
                platform = "macos-x86_64";
                ext = ".dylib";
            } else if (isLinux()) {
                platform = "linux-x86_64";
                ext = ".so";
            }
        } else if (isArm64()) {
            if (isMac()) {
                platform = "macos-aarch64";
                ext = ".dylib";
            } if (isLinux()) {
                platform = "linux-aarch64";
                ext = ".so";
            }
        }

        if (platform == null) {
            return null;
        }

        return "lib" + libName + "-" + platform + ext;
    }

    private static void copyNativeLib(String libName, Path libPath)
            throws IOException {
        try (InputStream is = NativeCrypto.class.getResourceAsStream("/" + libName);
             OutputStream os = Files.newOutputStream(
                     libPath,
                     StandardOpenOption.CREATE,
                     StandardOpenOption.WRITE,
                     StandardOpenOption.TRUNCATE_EXISTING)) {
            byte[] buffer = new byte[16 * 1024];
            for (int len = is.read(buffer); len >= 0; len = is.read(buffer)) {
                os.write(buffer, 0, len);
            }
        }
    }

    private static class InstanceHolder {
        private static final NativeCrypto INSTANCE = new NativeCrypto();
    }

    static NativeCrypto nativeCrypto() {
        return InstanceHolder.INSTANCE;
    }

    private NativeCrypto() {}

    static final int OPENSSL_SUCCESS = 1;
    static final int OPENSSL_FAILURE = 0;

    /* ***** SM3 ***** */
    native long   sm3CreateCtx();
    native void   sm3FreeCtx(long pointer);
    native int    sm3Update(long pointer, byte[] data);
    native byte[] sm3Final(long pointer);
    native int    sm3Reset(long pointer);
    native long   sm3Clone(long pointer);
    static native byte[] sm3OneShotDigest(byte[] data);

    /* ***** SM3HMAC ***** */
    native long   sm3hmacCreateCtx(byte[] key);
    native void   sm3hmacFreeCtx(long pointer);
    native int    sm3hmacUpdate(long pointer, byte[] data);
    native byte[] sm3hmacFinal(long pointer);
    native int    sm3hmacReset(long pointer);
    native long   sm3hmacClone(long pointer);
    static native byte[] sm3hmacOneShotMac(byte[] key, byte[] data);

    /* ***** SM4 ***** */
    native long   sm4CreateCtx(boolean encrypt, String mode, boolean padding, byte[] key, byte[] iv);
    native void   sm4FreeCtx(long pointer);
    native byte[] sm4Update(long pointer, byte[] in);
    native byte[] sm4Final(long pointer, byte[] key, byte[] iv);
    native int    sm4GCMSetIV(long pointer, byte[] iv);
    native int    sm4GCMUpdateAAD(long pointer, byte[] aad);
    native int    sm4GCMProcTag(long pointer, byte[] tag);

    /* ***** SM2 ***** */
    static native byte[] sm2ToUncompPubKey(byte[] compPubKey);
    static native byte[] sm2GenPubKey(byte[] priKey);
    static native int    sm2ValidatePoint(byte[] point);

    native long   sm2KeyPairGenCreateCtx();
    native void   sm2KeyPairGenFreeCtx(long pointer);
    native byte[] sm2KeyPairGenGenKeyPair(long pointer);
    static native byte[] sm2OneShotKeyPairGenGenKeyPair();

    native long   sm2CipherCreateCtx(byte[] key);
    native void   sm2CipherFreeCtx(long pointer);
    native byte[] sm2CipherEncrypt(long pointer, byte[] plaintext);
    native byte[] sm2CipherDecrypt(long pointer, byte[] ciphertext);
    static native byte[] sm2OneShotCipherEncrypt(byte[] key, byte[] plaintext);
    static native byte[] sm2OneShotCipherDecrypt(byte[] key, byte[] ciphertext);

    native long   sm2SignatureCreateCtx(byte[] key, byte[] id, boolean isSign);
    native void   sm2SignatureFreeCtx(long pointer);
    native byte[] sm2SignatureSign(long pointer, byte[] message);
    native int    sm2SignatureVerify(long pointer, byte[] message, byte[] signature);
    static native byte[] sm2OneShotSignatureSign(byte[] key, byte[] id, byte[] message);
    static native int    sm2OneShotSignatureVerify(byte[] key, byte[] id, byte[] message, byte[] signature);

    native long   sm2KeyExCreateCtx();
    native void   sm2KeyExFreeCtx(long pointer);
    native byte[] sm2DeriveKey(long pointer,
                               byte[] priKey, byte[] pubKey, byte[] ePrivKey, byte[] id,
                               byte[] peerPubKey, byte[] peerEPubKey, byte[] peerId,
                               boolean isInitiator, int sharedKeyLength);
    static native byte[] sm2OneShotDeriveKey(
                               byte[] priKey, byte[] pubKey, byte[] ePrivKey, byte[] id,
                               byte[] peerPubKey, byte[] peerEPubKey, byte[] peerId,
                               boolean isInitiator, int sharedKeyLength);

    /* ***** ECC ***** */
    static native Object[] ecOneShotKeyPairGenGenKeyPair(int curveNID);
    static native long     ecKeyPairGenCreateCtx(int curveNID);
    static native void     ecKeyPairGenFreeCtx(long pointer);
    static native Object[] ecKeyPairGenGenKeyPair(long pointer);

    static native long   ecdsaCreateCtx(int mdNID, int curveNID, byte[] key, boolean isSign);
    static native void   ecdsaFreeCtx(long pointer);
    static native byte[] ecdsaSign(long pointer, byte[] message);
    static native int    ecdsaVerify(long pointer, byte[] message, byte[] signature);
    static native byte[] ecdsaOneShotSign(int mdNID, int curveNID, byte[] key, byte[] message);
    static native int    ecdsaOneShotVerify(int mdNID, int curveNID, byte[] key, byte[] message, byte[] signature);
}
