/*
 * Copyright (C) 2024, 2025, Tencent. All rights reserved.
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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.util.Arrays;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.provider.nativeImpl.NativeSM4.*;

/**
 * The test for native SM4 implementation.
 */
@EnabledOnOs(OS.LINUX)
public class NativeSM4Test {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] ALT_KEY = toBytes("0123456789abcdef0123456789abcdef01");
    private static final byte[] IV = toBytes("00000000000000000000000000000001");
    private static final byte[] ALT_IV = toBytes("00000000000000000000000000000002");
    private static final byte[] GCM_IV = toBytes("000000000000000000000003");
    private static final byte[] ALT_GCM_IV = toBytes("000000000000000000000004");
    private static final byte[] AAD = toBytes("616263");
    private static final byte[] ALT_AAD = toBytes("010203");

    private static final byte[] EMPTY = new byte[0];

    private static final byte[] MESSAGE_15 = toBytes(
            "0123456789abcdef0123456789abcd");
    private static final byte[] MESSAGE_31 = toBytes(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd");
    private static final byte[] MESSAGE_32 = toBytes(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    @Test
    public void testCBCNoPadding() {
        try(SM4CBC encrypter = new SM4CBC(true, false, KEY, IV)) {
            byte[] ciphertext = encrypter.doFinal(MESSAGE_32);

            try(SM4CBC decrypter = new SM4CBC(false, false, KEY, IV)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(MESSAGE_32, plaintext);
            }
        }
    }

    @Test
    public void testCBCNoPaddingWithBadIV() {
        try(SM4CBC encrypter = new SM4CBC(true, false, KEY, IV)) {
            byte[] ciphertext = encrypter.doFinal(MESSAGE_32);

            try(SM4CBC decrypter = new SM4CBC(false, false, KEY, ALT_IV)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertFalse(Arrays.equals(MESSAGE_32, plaintext));
            }
        }
    }

    @Test
    public void testCBCNoPaddingWithNonFullBlock() {
        try(SM4CBC encrypter = new SM4CBC(true, false, KEY, IV)) {
            Assertions.assertThrows(
                    IllegalStateException.class,
                    () -> encrypter.doFinal(MESSAGE_15));
        }

        try(SM4CBC encrypter = new SM4CBC(false, false, KEY, IV)) {
            Assertions.assertThrows(
                    IllegalStateException.class,
                    () -> encrypter.doFinal(MESSAGE_31));
        }
    }

    @Test
    public void testCBCNoPaddingWithEmptyData() {
        try(SM4CBC encrypter = new SM4CBC(true, false, KEY, IV)) {
            byte[] ciphertext = encrypter.doFinal(EMPTY);

            try(SM4CBC decrypter = new SM4CBC(false, false, KEY, IV)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(EMPTY, plaintext);
            }
        }
    }

    @Test
    public void testCBCNoPaddingWithNullData() {
        try(SM4CBC encrypter = new SM4CBC(true, false, KEY, IV)) {
            Assertions.assertThrows(
                    NullPointerException.class,
                    () -> encrypter.doFinal(null));
        }
    }

    @Test
    public void testCBCPadding() {
        try(SM4CBC encrypter = new SM4CBC(true, true, KEY, IV)) {
            byte[] ciphertext = encrypter.doFinal(MESSAGE_32);

            try(SM4CBC decrypter = new SM4CBC(false, true, KEY, IV)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(MESSAGE_32, plaintext);
            }
        }
    }

    @Test
    public void testCBCPaddingWithBadIV() {
        try(SM4CBC encrypter = new SM4CBC(true, true, KEY, IV)) {
            byte[] ciphertext = encrypter.doFinal(MESSAGE_32);

            try(SM4CBC decrypter = new SM4CBC(false, true, KEY, ALT_IV)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertFalse(Arrays.equals(MESSAGE_32, plaintext));
            }
        }
    }

    @Test
    public void testCBCPaddingWithNonFullBlock() {
        try(SM4CBC encrypter = new SM4CBC(true, true, KEY, IV)) {
            byte[] ciphertext = encrypter.doFinal(MESSAGE_15);

            try(SM4CBC decrypter = new SM4CBC(false, true, KEY, IV)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(MESSAGE_15, plaintext);
            }
        }
    }

    @Test
    public void testCBCPaddingWithEmptyData() {
        try(SM4CBC encrypter = new SM4CBC(true, true, KEY, IV)) {
            byte[] ciphertext = encrypter.doFinal(EMPTY);

            try(SM4CBC decrypter = new SM4CBC(false, true, KEY, IV)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(EMPTY, plaintext);
            }
        }
    }

    @Test
    public void testCBCPaddingWithNullData() {
        try(SM4CBC encrypter = new SM4CBC(true, true, KEY, IV)) {
            Assertions.assertThrows(
                    NullPointerException.class,
                    () -> encrypter.doFinal(null));
        }
    }

    @Test
    public void testUseClosedCBCRef() {
        SM4CBC sm4 = new SM4CBC(true, false, KEY, IV);
        sm4.close();

        Assertions.assertThrows(
                IllegalStateException.class,
                () -> sm4.doFinal(MESSAGE_32));
    }

    @Test
    public void testCloseCBCTwice() {
        SM4CBC sm4 = new SM4CBC(true, false, KEY, IV);
        sm4.close();
        sm4.close();
    }

    @Test
    public void testCTR() {
        try(SM4CTR encrypter = new SM4CTR(true, KEY, IV)) {
            byte[] ciphertext = encrypter.doFinal(MESSAGE_32);

            try(SM4CTR decrypter = new SM4CTR(false, KEY, IV)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(MESSAGE_32, plaintext);
            }
        }
    }

    @Test
    public void testCTRWithBadIV() {
        try(SM4CTR encrypter = new SM4CTR(true, KEY, IV)) {
            byte[] ciphertext = encrypter.doFinal(MESSAGE_32);

            try(SM4CTR decrypter = new SM4CTR(false, KEY, ALT_IV)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertFalse(Arrays.equals(MESSAGE_32, plaintext));
            }
        }
    }

    @Test
    public void testCTRWithDifferentIV() {
        try(SM4CTR encrypter1 = new SM4CTR(true, KEY, IV)) {
            byte[] ciphertext1 = encrypter1.doFinal(MESSAGE_32);

            try(SM4CTR encrypter2 = new SM4CTR(false, KEY, ALT_IV)) {
                byte[] ciphertext2 = encrypter2.doFinal(MESSAGE_32);
                Assertions.assertFalse(Arrays.equals(ciphertext1, ciphertext2));
            }
        }
    }

    @Test
    public void testCTRWithNonFullBlock() {
        try(SM4CTR encrypter = new SM4CTR(true, KEY, IV)) {
            byte[] ciphertext = encrypter.doFinal(MESSAGE_15);

            try(SM4CTR decrypter = new SM4CTR(false, KEY, IV)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(MESSAGE_15, plaintext);
            }
        }

        try(SM4CTR encrypter = new SM4CTR(true, KEY, IV)) {
            byte[] ciphertext = encrypter.doFinal(MESSAGE_31);

            try(SM4CTR decrypter = new SM4CTR(false, KEY, IV)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(MESSAGE_31, plaintext);
            }
        }
    }

    @Test
    public void testCTRWithEmptyData() {
        try(SM4CTR encrypter = new SM4CTR(true, KEY, IV)) {
            byte[] ciphertext = encrypter.doFinal(EMPTY);

            try(SM4CTR decrypter = new SM4CTR(false, KEY, IV)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(EMPTY, plaintext);
            }
        }
    }

    @Test
    public void testCTRWithNullData() {
        try(SM4CTR encrypter = new SM4CTR(true, KEY, IV)) {
            Assertions.assertThrows(
                    NullPointerException.class,
                    () -> encrypter.doFinal(null));
        }
    }

    @Test
    public void testUseClosedCTRRef() {
        SM4CTR sm4 = new SM4CTR(true, KEY, IV);
        sm4.close();

        Assertions.assertThrows(
                IllegalStateException.class,
                () -> sm4.doFinal(MESSAGE_32));
    }

    @Test
    public void testCloseCTRTwice() {
        SM4CTR sm4 = new SM4CTR(true, KEY, IV);
        sm4.close();
        sm4.close();
    }

    @Test
    public void testECBNoPadding() {
        try(SM4ECB encrypter = new SM4ECB(true, false, KEY)) {
            byte[] ciphertext = encrypter.doFinal(MESSAGE_32);

            try(SM4ECB decrypter = new SM4ECB(false, false, KEY)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(MESSAGE_32, plaintext);
            }
        }
    }

    @Test
    public void testECBNoPaddingWithNonFullBlock() {
        try(SM4ECB encrypter = new SM4ECB(true, false, KEY)) {
            Assertions.assertThrows(
                    IllegalStateException.class,
                    () -> encrypter.doFinal(MESSAGE_15));
        }

        try(SM4ECB encrypter = new SM4ECB(false, false, KEY)) {
            Assertions.assertThrows(
                    IllegalStateException.class,
                    () -> encrypter.doFinal(MESSAGE_31));
        }
    }

    @Test
    public void testECBNoPaddingWithEmptyData() {
        try(SM4ECB encrypter = new SM4ECB(true, false, KEY)) {
            byte[] ciphertext = encrypter.doFinal(EMPTY);

            try(SM4ECB decrypter = new SM4ECB(false, false, KEY)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(EMPTY, plaintext);
            }
        }
    }

    @Test
    public void testECBNoPaddingWithNullData() {
        try(SM4ECB encrypter = new SM4ECB(true, false, KEY)) {
            Assertions.assertThrows(
                    NullPointerException.class,
                    () -> encrypter.doFinal(null));
        }
    }

    @Test
    public void testECBPPadding() {
        try(SM4ECB encrypter = new SM4ECB(true, true, KEY)) {
            byte[] ciphertext = encrypter.doFinal(MESSAGE_32);

            try(SM4ECB decrypter = new SM4ECB(false, true, KEY)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(MESSAGE_32, plaintext);
            }
        }
    }

    @Test
    public void testECBPaddingWithNonFullBlock() {
        try(SM4ECB encrypter = new SM4ECB(true, true, KEY)) {
            byte[] ciphertext = encrypter.doFinal(MESSAGE_15);

            try(SM4ECB decrypter = new SM4ECB(false, true, KEY)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(MESSAGE_15, plaintext);
            }
        }
    }

    @Test
    public void testEBCPaddingWithEmptyData() {
        try(SM4ECB encrypter = new SM4ECB(true, true, KEY)) {
            byte[] ciphertext = encrypter.doFinal(EMPTY);

            try(SM4ECB decrypter = new SM4ECB(false, true, KEY)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(EMPTY, plaintext);
            }
        }
    }

    @Test
    public void testECBPaddingWithNullData() {
        try(SM4ECB encrypter = new SM4ECB(true, true, KEY)) {
            Assertions.assertThrows(
                    NullPointerException.class,
                    () -> encrypter.doFinal(null));
        }
    }

    @Test
    public void testUseClosedECBRef() {
        SM4ECB sm4 = new SM4ECB(true, false, KEY);
        sm4.close();

        Assertions.assertThrows(
                IllegalStateException.class,
                () -> sm4.doFinal(MESSAGE_32));
    }

    @Test
    public void testCloseECBTwice() {
        SM4ECB sm4 = new SM4ECB(true, false, KEY);
        sm4.close();
        sm4.close();
    }

    @Test
    public void testGCM() {
        try(SM4GCM encrypter = new SM4GCM(true, KEY, GCM_IV)) {
            byte[] ciphertext = encrypter.doFinal(MESSAGE_32);

            try(SM4GCM decrypter = new SM4GCM(false, KEY, GCM_IV)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(MESSAGE_32, plaintext);
            }
        }
    }

    @Test
    public void testGCMWithBadIV() {
        try(SM4GCM encrypter = new SM4GCM(true, KEY, GCM_IV)) {
            byte[] ciphertext = encrypter.doFinal(MESSAGE_32);

            try(SM4GCM decrypter = new SM4GCM(false, KEY, ALT_GCM_IV)) {
                Assertions.assertThrows(
                        IllegalStateException.class,
                        () -> decrypter.doFinal(ciphertext));
            }
        }
    }

    @Test
    public void testGCMWithBadTag() {
        try(SM4GCM encrypter = new SM4GCM(true, KEY, GCM_IV)) {
            byte[] ciphertext = encrypter.doFinal(MESSAGE_32);
            ciphertext[ciphertext.length - 1] = 0x00; // change the tag a bit

            try(SM4GCM decrypter = new SM4GCM(false, KEY, GCM_IV)) {
                Assertions.assertThrows(
                        IllegalStateException.class,
                        () -> decrypter.doFinal(ciphertext));
            }
        }
    }

    @Test
    public void testGCMAAD() {
        try(SM4GCM encrypter = new SM4GCM(true, KEY, GCM_IV)) {
            encrypter.updateAAD(AAD);
            byte[] ciphertext = encrypter.doFinal(MESSAGE_32);

            try(SM4GCM decrypter = new SM4GCM(false, KEY, GCM_IV)) {
                decrypter.updateAAD(AAD);
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(MESSAGE_32, plaintext);
            }
        }
    }

    @Test
    public void testGCMWithBadAAD() {
        try(SM4GCM encrypter = new SM4GCM(true, KEY, GCM_IV)) {
            encrypter.updateAAD(AAD);
            byte[] ciphertext = encrypter.doFinal(MESSAGE_32);

            try(SM4GCM decrypter = new SM4GCM(false, KEY, GCM_IV)) {
                decrypter.updateAAD(ALT_AAD);
                Assertions.assertThrows(
                        IllegalStateException.class,
                        () -> decrypter.doFinal(ciphertext));

            }
        }
    }

    @Test
    public void testGCMWithNonFullBlock() {
        try(SM4GCM encrypter = new SM4GCM(true, KEY, GCM_IV)) {
            byte[] ciphertext = encrypter.doFinal(MESSAGE_15);

            try(SM4GCM decrypter = new SM4GCM(false, KEY, GCM_IV)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(MESSAGE_15, plaintext);
            }
        }

        try(SM4GCM encrypter = new SM4GCM(true, KEY, GCM_IV)) {
            byte[] ciphertext = encrypter.doFinal(MESSAGE_31);

            try(SM4GCM decrypter = new SM4GCM(false, KEY, GCM_IV)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(MESSAGE_31, plaintext);
            }
        }
    }

    @Test
    public void testGCMWithEmptyData() {
        try(SM4GCM encrypter = new SM4GCM(true, KEY, GCM_IV)) {
            byte[] ciphertext = encrypter.doFinal(EMPTY);

            try(SM4GCM decrypter = new SM4GCM(false, KEY, GCM_IV)) {
                byte[] plaintext = decrypter.doFinal(ciphertext);
                Assertions.assertArrayEquals(EMPTY, plaintext);
            }
        }
    }

    @Test
    public void testGCMWithNullData() {
        try(SM4GCM encrypter = new SM4GCM(true, KEY, GCM_IV)) {
            Assertions.assertThrows(
                    NullPointerException.class,
                    () -> encrypter.doFinal(null));
        }
    }

    @Test
    public void testUseClosedGCMRef() {
        SM4GCM sm4 = new SM4GCM(false, KEY, GCM_IV);
        sm4.close();

        Assertions.assertThrows(
                IllegalStateException.class,
                () -> sm4.doFinal(MESSAGE_32));
    }

    @Test
    public void testCloseGCMTwice() {
        SM4GCM sm4 = new SM4GCM(false, KEY, GCM_IV);
        sm4.close();
        sm4.close();
    }

    @Test
    public void testKey() {
        Assertions.assertThrows(
                IllegalStateException.class,
                ()-> new SM4ECB(true, false, ALT_KEY).close());
        Assertions.assertThrows(
                IllegalStateException.class,
                ()-> new SM4ECB(true, false, EMPTY).close());
        Assertions.assertThrows(
                IllegalStateException.class,
                ()-> new SM4ECB(true, false, null).close());
    }

    @Test
    public void testIV() {
        Assertions.assertThrows(
                IllegalStateException.class,
                ()-> new SM4CBC(true, false, KEY, GCM_IV).close());
        Assertions.assertThrows(
                IllegalStateException.class,
                ()-> new SM4CTR(true, KEY, GCM_IV).close());
        Assertions.assertThrows(
                IllegalStateException.class,
                ()-> new SM4GCM(true, KEY, IV).close());
    }
}
