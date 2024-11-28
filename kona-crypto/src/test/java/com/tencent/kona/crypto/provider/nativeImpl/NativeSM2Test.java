/*
 * Copyright (C) 2024, THL A29 Limited, a Tencent company. All rights reserved.
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

import com.tencent.kona.crypto.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import javax.crypto.BadPaddingException;

import static com.tencent.kona.crypto.CryptoUtils.*;
import static com.tencent.kona.crypto.util.Constants.*;

/**
 * The test for native SM2 implementation.
 */
@EnabledOnOs(OS.LINUX)
public class NativeSM2Test {

    private final static String PUB_KEY_ODD
            = "0475C05A9371F2CED4573FB2CFD10A36C00294F34582BCBA257817B973902A81C5F7C4AD1A3DDDD5C57FE16B15F841CA075FC05D19872D1BC0CCD5E69690F76955";
    private static final String COMP_PUB_KEY_ODD = "0375C05A9371F2CED4573FB2CFD10A36C00294F34582BCBA257817B973902A81C5";

    private final static String PUB_KEY_EVEN
            = "04C1BE22935ED71A406E2B1B3E5F163582E016FC58E7E676B0FDADD215457EAD67C03BFFC35CA94FCF6011E27B46A7A12C6530C56D454D073E6903AAEE1DEF567C";
    private static final String COMP_PUB_KEY_EVEN = "02C1BE22935ED71A406E2B1B3E5F163582E016FC58E7E676B0FDADD215457EAD67";

    private static final byte[] MESSAGE = "message".getBytes();
    private static final byte[] EMPTY = new byte[0];

    private static final byte[] ID = "012345678012345678".getBytes();

    @Test
    public void testToUncompPubKey() {
        testToUncompPubKey(toBytes(PUB_KEY_ODD), toBytes(COMP_PUB_KEY_ODD));
        testToUncompPubKey(toBytes(PUB_KEY_EVEN), toBytes(COMP_PUB_KEY_EVEN));
    }

    private void testToUncompPubKey(byte[] expectedPubKey, byte[] compPubKey) {
        byte[] uncompPubKey = NativeCrypto.nativeCrypto().sm2ToUncompPubKey(compPubKey);
        Assertions.assertArrayEquals(expectedPubKey, uncompPubKey);
    }

    @Test
    public void testToUncompPubKeyParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testToUncompPubKey();
            return null;
        });
    }

    @Test
    public void testToUncompPubKeySerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testToUncompPubKey();
            return null;
        });
    }

    @Test
    public void testSM2GenPubKey() {
        try (NativeSM2KeyPairGen sm2 = new NativeSM2KeyPairGen()) {
            byte[] keyPair = sm2.genKeyPair();
            byte[] pubKey = NativeCrypto.nativeCrypto().sm2GenPubKey(copy(keyPair, 0, SM2_PRIKEY_LEN));
            Assertions.assertArrayEquals(copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN), pubKey);
        }
    }

    @Test
    public void testSM2GenPubKeyParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testSM2GenPubKey();
            return null;
        });
    }

    @Test
    public void testSM2GenPubKeySerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testSM2GenPubKey();
            return null;
        });
    }

    @Test
    public void testSM2KeyPairGenGenKeyPair() {
        try (NativeSM2KeyPairGen sm2 = new NativeSM2KeyPairGen()) {
            byte[] keyPair = sm2.genKeyPair();
            Assertions.assertEquals(SM2_PRIKEY_LEN + SM2_PUBKEY_LEN, keyPair.length);
        }
    }

    @Test
    public void testSM2KeyPairGenGenKeyPairParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testSM2KeyPairGenGenKeyPair();
            return null;
        });
    }

    @Test
    public void testSM2KeyPairGenGenKeyPairSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testSM2KeyPairGenGenKeyPair();
            return null;
        });
    }

    @Test
    public void testSM2KeyPairGenUseClosedRef() {
        NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen();
        sm2KeyPairGen.genKeyPair();
        sm2KeyPairGen.close();

        Assertions.assertThrows(
                IllegalStateException.class,
                sm2KeyPairGen::genKeyPair);
    }

    @Test
    public void testSM2Cipher() throws Exception {
        try (NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen()) {
            byte[] keyPair = sm2KeyPairGen.genKeyPair();
            byte[] priKey = copy(keyPair, 0, SM2_PRIKEY_LEN);
            byte[] pubKey = copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

            try (NativeSM2Cipher sm2Encrypter = new NativeSM2Cipher(pubKey)) {
                byte[] ciphertext = sm2Encrypter.encrypt(MESSAGE);

                try (NativeSM2Cipher sm2Decrypter = new NativeSM2Cipher(priKey)) {
                    byte[] cleartext = sm2Decrypter.decrypt(ciphertext);

                    Assertions.assertArrayEquals(MESSAGE, cleartext);
                }
            }
        }
    }

    @Test
    public void testSM2CipherWithKeyPair() throws Exception {
        try (NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen()) {
            byte[] keyPair = sm2KeyPairGen.genKeyPair();

            try (NativeSM2Cipher sm2Encrypter = new NativeSM2Cipher(keyPair)) {
                byte[] ciphertext = sm2Encrypter.encrypt(MESSAGE);

                try (NativeSM2Cipher sm2Decrypter = new NativeSM2Cipher(keyPair)) {
                    byte[] cleartext = sm2Decrypter.decrypt(ciphertext);

                    Assertions.assertArrayEquals(MESSAGE, cleartext);
                }
            }
        }
    }

    @Test
    public void testSM2CipherParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testSM2Cipher();
            return null;
        });
    }

    @Test
    public void testSM2CipherSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testSM2Cipher();
            return null;
        });
    }

    @Test
    public void testSM2CipherEmptyInput() {
        try (NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen()) {
            byte[] keyPair = sm2KeyPairGen.genKeyPair();

            try (NativeSM2Cipher sm2Encrypter = new NativeSM2Cipher(keyPair)) {
                Assertions.assertThrows(BadPaddingException.class,
                        () -> sm2Encrypter.encrypt(EMPTY));
            }

            try (NativeSM2Cipher sm2Decrypter = new NativeSM2Cipher(keyPair)) {
                Assertions.assertThrows(BadPaddingException.class,
                        () -> sm2Decrypter.decrypt(EMPTY));
            }
        }
    }

    @Test
    public void testSM2CipherNullInput() {
        try (NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen()) {
            byte[] keyPair = sm2KeyPairGen.genKeyPair();

            try (NativeSM2Cipher sm2Encrypter = new NativeSM2Cipher(keyPair)) {
                Assertions.assertThrows(BadPaddingException.class,
                        () -> sm2Encrypter.encrypt(null));
            }

            try (NativeSM2Cipher sm2Decrypter = new NativeSM2Cipher(keyPair)) {
                Assertions.assertThrows(BadPaddingException.class,
                        () -> sm2Decrypter.decrypt(null));
            }
        }
    }

    @Test
    public void testSM2CipherUseClosedRef() {
        try (NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen()) {
            byte[] keyPair = sm2KeyPairGen.genKeyPair();

            NativeSM2Cipher sm2Encrypter = new NativeSM2Cipher(keyPair);
            sm2Encrypter.close();
            Assertions.assertThrows(BadPaddingException.class,
                    () -> sm2Encrypter.encrypt(EMPTY));

            NativeSM2Cipher sm2Decrypter = new NativeSM2Cipher(keyPair);
            sm2Decrypter.close();
            Assertions.assertThrows(BadPaddingException.class,
                    () -> sm2Decrypter.decrypt(EMPTY));
        }
    }

    @Test
    public void testSM2Signature() throws Exception {
        try (NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen()) {
            byte[] keyPair = sm2KeyPairGen.genKeyPair();
            byte[] priKey = copy(keyPair, 0, SM2_PRIKEY_LEN);
            byte[] pubKey = copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

            try (NativeSM2Signature sm2Signer
                         = new NativeSM2Signature(priKey, null, ID, true)) {
                byte[] signature = sm2Signer.sign(MESSAGE);

                try (NativeSM2Signature sm2Verifier
                             = new NativeSM2Signature(pubKey, ID, false)) {
                    boolean verified = sm2Verifier.verify(MESSAGE, signature);

                    Assertions.assertTrue(verified);
                }
            }
        }
    }

    @Test
    public void testSM2SignatureWithKeyPair() throws Exception {
        try (NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen()) {
            byte[] keyPair = sm2KeyPairGen.genKeyPair();
            byte[] priKey = copy(keyPair, 0, SM2_PRIKEY_LEN);
            byte[] pubKey = copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

            try (NativeSM2Signature sm2Signer
                         = new NativeSM2Signature(priKey, pubKey, ID, true)) {
                byte[] signature = sm2Signer.sign(MESSAGE);

                try (NativeSM2Signature sm2Verifier
                             = new NativeSM2Signature(pubKey, ID, false)) {
                    boolean verified = sm2Verifier.verify(MESSAGE, signature);

                    Assertions.assertTrue(verified);
                }
            }
        }
    }

    @Test
    public void testSM2SignatureParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testSM2Signature();
            return null;
        });
    }

    @Test
    public void testSM2SignatureSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testSM2Signature();
            return null;
        });
    }

    @Test
    public void testSM2SignatureEmptyInput() throws Exception {
        try (NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen()) {
            byte[] keyPair = sm2KeyPairGen.genKeyPair();
            byte[] priKey = copy(keyPair, 0, SM2_PRIKEY_LEN);
            byte[] pubKey = copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

            try (NativeSM2Signature sm2Signer
                         = new NativeSM2Signature(priKey, pubKey, ID, true)) {
                byte[] signature = sm2Signer.sign(EMPTY);

                try (NativeSM2Signature sm2Verifier
                             = new NativeSM2Signature(pubKey, ID, false)) {
                    boolean verified = sm2Verifier.verify(EMPTY, signature);

                    Assertions.assertTrue(verified);
                }
            }
        }
    }

    @Test
    public void testSM2SignatureNullInput() {
        try (NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen()) {
            byte[] keyPair = sm2KeyPairGen.genKeyPair();
            byte[] priKey = copy(keyPair, 0, SM2_PRIKEY_LEN);
            byte[] pubKey = copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

            try (NativeSM2Signature sm2Signer
                         = new NativeSM2Signature(priKey, pubKey, ID, true)) {
                Assertions.assertThrows(BadPaddingException.class,
                        () -> sm2Signer.sign(null));
            }

            try (NativeSM2Signature sm2Verifier
                         = new NativeSM2Signature(pubKey, ID, false)) {
                Assertions.assertThrows(BadPaddingException.class,
                        () -> sm2Verifier.verify(MESSAGE, null));
            }
        }
    }

    @Test
    public void testSM2SignatureUseClosedRef() {
        try (NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen()) {
            byte[] keyPair = sm2KeyPairGen.genKeyPair();
            byte[] priKey = copy(keyPair, 0, SM2_PRIKEY_LEN);
            byte[] pubKey = copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

            NativeSM2Signature sm2Signer = new NativeSM2Signature(priKey, pubKey, ID, true);
            sm2Signer.close();
            Assertions.assertThrows(BadPaddingException.class,
                    () -> sm2Signer.sign(MESSAGE));

            NativeSM2Signature sm2Verifier = new NativeSM2Signature(pubKey, ID, false);
            sm2Verifier.close();
            Assertions.assertThrows(BadPaddingException.class,
                    () -> sm2Verifier.verify(MESSAGE, null));
        }
    }
}
