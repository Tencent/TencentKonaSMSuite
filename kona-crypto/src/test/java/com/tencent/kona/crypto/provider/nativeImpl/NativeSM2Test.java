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
import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.util.Constants.*;

/**
 * The test for native SM2 implementation.
 */
@EnabledOnOs(OS.LINUX)
public class NativeSM2Test {

    private final static byte[] PUB_KEY_ODD
            = toBytes("0475C05A9371F2CED4573FB2CFD10A36C00294F34582BCBA257817B973902A81C5F7C4AD1A3DDDD5C57FE16B15F841CA075FC05D19872D1BC0CCD5E69690F76955");
    private static final byte[] COMP_PUB_KEY_ODD
            = toBytes("0375C05A9371F2CED4573FB2CFD10A36C00294F34582BCBA257817B973902A81C5");

    private final static byte[] PUB_KEY_EVEN
            = toBytes("04C1BE22935ED71A406E2B1B3E5F163582E016FC58E7E676B0FDADD215457EAD67C03BFFC35CA94FCF6011E27B46A7A12C6530C56D454D073E6903AAEE1DEF567C");
    private static final byte[] COMP_PUB_KEY_EVEN
            = toBytes("02C1BE22935ED71A406E2B1B3E5F163582E016FC58E7E676B0FDADD215457EAD67");

    private static final byte[] MESSAGE = "message".getBytes();
    private static final byte[] EMPTY = new byte[0];

    private static final byte[] ID
            = toBytes("31323334353637383132333435363738");
    private static final byte[] PRI_KEY
            = toBytes("81EB26E941BB5AF16DF116495F90695272AE2CD63D6C4AE1678418BE48230029");
    private static final byte[] PUB_KEY
            = toBytes("04160E12897DF4EDB61DD812FEB96748FBD3CCF4FFE26AA6F6DB9540AF49C942324A7DAD08BB9A459531694BEB20AA489D6649975E1BFCF8C4741B78B4B223007F");
    private static final byte[] E_PRI_KEY
            = toBytes("D4DE15474DB74D06491C440D305E012400990F3E390C7E87153C12DB2EA60BB3");
    private static final byte[] E_PUB_KEY
            = toBytes("0464CED1BDBC99D590049B434D0FD73428CF608A5DB8FE5CE07F15026940BAE40E376629C7AB21E7DB260922499DDB118F07CE8EAAE3E7720AFEF6A5CC062070C0");

    private static final byte[] PEER_ID
            = toBytes("31323334353637383132333435363738");
    private static final byte[] PEER_PRI_KEY
            = toBytes("785129917D45A9EA5437A59356B82338EAADDA6CEB199088F14AE10DEFA229B5");
    private static final byte[] PEER_PUB_KEY
            = toBytes("046AE848C57C53C7B1B5FA99EB2286AF078BA64C64591B8B566F7357D576F16DFBEE489D771621A27B36C5C7992062E9CD09A9264386F3FBEA54DFF69305621C4D");
    private static final byte[] PEER_E_PRI_KEY
            = toBytes("7E07124814B309489125EAED101113164EBF0F3458C5BD88335C1F9D596243D6");
    private static final byte[] PEER_E_PUB_KEY
            = toBytes("04ACC27688A6F7B706098BC91FF3AD1BFF7DC2802CDB14CCCCDB0A90471F9BD7072FEDAC0494B2FFC4D6853876C79B8F301C6573AD0AA50F39FC87181E1A1B46FE");

    private final static byte[] SHARED_KEY = toBytes("6C89347354DE2484C60B4AB1FDE4C6E5");

    @Test
    public void testToUncompPubKey() {
        testToUncompPubKey(PUB_KEY_ODD, COMP_PUB_KEY_ODD);
        testToUncompPubKey(PUB_KEY_EVEN, COMP_PUB_KEY_EVEN);
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

    @Test
    public void testSM2KeyAgreement() {
        try (NativeSM2KeyAgreement sm2KeyAgreement
                     = new NativeSM2KeyAgreement()) {
            byte[] sharedKey = sm2KeyAgreement.deriveKey(
                    PRI_KEY, PUB_KEY, E_PRI_KEY, ID,
                    PEER_PUB_KEY, PEER_E_PUB_KEY, PEER_ID,
                    true, 16);

            Assertions.assertEquals(16, sharedKey.length);
        }
    }

    @Test
    public void testSM2KeyAgreementWithKeyPair() {
        try (NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen()) {
            byte[] keyPair = sm2KeyPairGen.genKeyPair();
            byte[] priKey = copy(keyPair, 0, SM2_PRIKEY_LEN);
            byte[] pubKey = copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

            byte[] eKeyPair = sm2KeyPairGen.genKeyPair();
            byte[] ePriKey = copy(eKeyPair, 0, SM2_PRIKEY_LEN);

            byte[] peerKeyPair = sm2KeyPairGen.genKeyPair();
            byte[] peerPubKey = copy(peerKeyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

            byte[] peerEKeyPair = sm2KeyPairGen.genKeyPair();
            byte[] peerEPubKey = copy(peerEKeyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

            try (NativeSM2KeyAgreement sm2KeyAgreement
                         = new NativeSM2KeyAgreement()) {
                byte[] sharedKey = sm2KeyAgreement.deriveKey(
                        priKey, pubKey, ePriKey, ID,
                        peerPubKey, peerEPubKey, PEER_ID,
                        true, 32);

                Assertions.assertEquals(32, sharedKey.length);
            }
        }
    }

    @Test
    public void testSM2KeyAgreementParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testSM2KeyAgreement();
            return null;
        });
    }

    @Test
    public void testSM2KeyAgreementSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testSM2KeyAgreement();
            return null;
        });
    }

    @Test
    public void testSM2KeyAgreementUseClosedRef() {
        try (NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen()) {
            byte[] keyPair = sm2KeyPairGen.genKeyPair();
            byte[] priKey = copy(keyPair, 0, SM2_PRIKEY_LEN);
            byte[] pubKey = copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

            byte[] eKeyPair = sm2KeyPairGen.genKeyPair();
            byte[] ePriKey = copy(eKeyPair, 0, SM2_PRIKEY_LEN);

            byte[] peerKeyPair = sm2KeyPairGen.genKeyPair();
            byte[] peerPubKey = copy(peerKeyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

            byte[] peerEKeyPair = sm2KeyPairGen.genKeyPair();
            byte[] peerEPubKey = copy(peerEKeyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

            NativeSM2KeyAgreement sm2KeyAgreement = new NativeSM2KeyAgreement();
            sm2KeyAgreement.close();
            Assertions.assertThrows(IllegalStateException.class,
                    () -> sm2KeyAgreement.deriveKey(
                            priKey, pubKey, ePriKey, ID,
                            peerPubKey, peerEPubKey, PEER_ID,
                            true, 32));
        }
    }
}
