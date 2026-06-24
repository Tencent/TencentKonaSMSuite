/*
 * Copyright (C) 2026, Tencent. All rights reserved.
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

package com.tencent.kona.crypto.provider.nativeImpl;

import com.tencent.kona.crypto.util.Sweeper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.lang.reflect.Field;
import java.time.Duration;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;

/**
 * Verifies that {@link SM4OneShotCrypt} actually releases its native context
 * when the cipher object is abandoned without ever calling {@code doFinal}.
 * <p>
 * Unlike the functional SM4 tests, this test observes the cleanup path itself:
 * the OneShot implementation has no automatic release on {@code doFinal} when
 * that call never happens, so without a Sweeper registration the native
 * context would leak. The test holds onto the inner {@link NativeSM4} (so it
 * survives GC), drops the owning {@link SM4OneShotCrypt}, and asserts that the
 * Sweeper eventually closes the native context (pointer reset to 0). Against an
 * implementation that does not register a Sweeper, the pointer would never be
 * reset and this test would time out / fail.
 */
@EnabledOnOs(OS.LINUX)
public class SM4OneShotCryptCleanupTest {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] IV = toBytes("00000000000000000000000000000001");
    private static final byte[] MESSAGE = toBytes(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    @Test
    public void testNativeContextReleasedWhenAbandonedWithoutDoFinal()
            throws Exception {
        NativeSM4 nativeSM4 = createAndAbandon();
        Assertions.assertNotNull(nativeSM4);

        // The native context must be live right after init()/update().
        Assertions.assertNotEquals(0L, pointerOf(nativeSM4),
                "native context should be allocated after init/update");

        // The owning SM4OneShotCrypt is now unreachable, but nativeSM4 is still
        // strongly held here. Once the Sweeper observes the owner becoming
        // phantom-reachable it runs SweepNativeRef, which closes nativeSM4 and
        // resets its pointer to 0.
        boolean released = waitUntil(
                () -> pointerOf(nativeSM4) == 0L,
                Duration.ofSeconds(30));

        Assertions.assertTrue(released,
                "native context was not released by the Sweeper; "
                        + "SM4OneShotCrypt likely lacks a Sweeper registration");
    }

    // Creates an SM4OneShotCrypt, initializes and feeds it data but never calls
    // doFinal, then returns only its inner NativeSM4 so the owning cipher
    // becomes eligible for GC once this method returns.
    private static NativeSM4 createAndAbandon() throws Exception {
        SM4OneShotCrypt crypt = new SM4OneShotCrypt();
        crypt.init(false, "SM4", KEY,
                new SM4Params(Mode.CBC, Padding.PKCS7Padding, IV));
        crypt.encryptBlock(MESSAGE, 0, MESSAGE.length);

        return extractNativeSM4(crypt);
    }

    private static NativeSM4 extractNativeSM4(SM4OneShotCrypt crypt)
            throws Exception {
        Field field = SM4OneShotCrypt.class.getDeclaredField("sm4");
        field.setAccessible(true);
        return (NativeSM4) field.get(crypt);
    }

    private static long pointerOf(NativeSM4 nativeSM4) {
        return nativeSM4.pointer;
    }

    private static boolean waitUntil(BooleanSupplierEx condition, Duration timeout)
            throws Exception {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            System.gc();
            System.runFinalization();
            if (condition.getAsBoolean()) {
                return true;
            }
            Thread.sleep(50);
        }
        return condition.getAsBoolean();
    }

    @FunctionalInterface
    private interface BooleanSupplierEx {
        boolean getAsBoolean();
    }
}
