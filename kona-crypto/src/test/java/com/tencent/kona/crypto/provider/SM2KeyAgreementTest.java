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

package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.TestUtils;
import com.tencent.kona.crypto.spec.SM2KeyAgreementParamSpec;
import com.tencent.kona.crypto.spec.SM2PrivateKeySpec;
import com.tencent.kona.crypto.spec.SM2PublicKeySpec;
import com.tencent.kona.sun.security.ec.ECOperator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The test for SM2 key agreement.
 */
public class SM2KeyAgreementTest {

    private final static String PUB_KEY
            = "041D9E2952A06C913BAD21CCC358905ADB3A8097DB6F2F87EB5F393284EC2B7208C30B4D9834D0120216D6F1A73164FDA11A87B0A053F63D992BFB0E4FC1C5D9AD";
    private final static String PRI_KEY
            = "3B03B35C2F26DBC56F6D33677F1B28AF15E45FE9B594A6426BDCAD4A69FF976B";
    private final static byte[] ID = toBytes("01234567");

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testParameterSpecOnId() throws Exception {
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("SM2", PROVIDER);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        SM2KeyAgreementParamSpec paramSpec = new SM2KeyAgreementParamSpec(
                ID,
                (ECPrivateKey) keyPair.getPrivate(),
                (ECPublicKey) keyPair.getPublic(),
                ID,
                (ECPublicKey) keyPair.getPublic(),
                true, 32);
        assertArrayEquals(ID, paramSpec.id());

        assertThrows(IllegalArgumentException.class,
                ()-> new SM2KeyAgreementParamSpec(
                        TestUtils.dataKB(8),
                        (ECPrivateKey) keyPair.getPrivate(),
                        (ECPublicKey) keyPair.getPublic(),
                        TestUtils.dataKB(1),
                        (ECPublicKey) keyPair.getPublic(),
                        true, 32));
        assertThrows(IllegalArgumentException.class,
                ()-> new SM2KeyAgreementParamSpec(
                        TestUtils.dataKB(1),
                        (ECPrivateKey) keyPair.getPrivate(),
                        (ECPublicKey) keyPair.getPublic(),
                        TestUtils.dataKB(8),
                        (ECPublicKey) keyPair.getPublic(),
                        true, 32));
        assertThrows(NullPointerException.class,
                ()-> new SM2KeyAgreementParamSpec(
                        TestUtils.dataKB(1),
                        (ECPrivateKey) keyPair.getPrivate(),
                        (ECPublicKey) keyPair.getPublic(),
                        TestUtils.dataKB(1), null,
                        true, 32));
    }

    @Test
    public void testParameterSpecOnPrivateKey() throws Exception {
        // privateKey = order - 1
        testParameterSpecOnPrivateKey(1);

        // privateKey = order
        assertThrows(IllegalArgumentException.class,
                () -> testParameterSpecOnPrivateKey(0));

        // privateKey = order + 1
        assertThrows(IllegalArgumentException.class,
                () -> testParameterSpecOnPrivateKey(-1));

    }

    private void testParameterSpecOnPrivateKey(int orderOffset)
            throws Exception {
        KeyPair keyPair = keyPair(orderOffset);
        new SM2KeyAgreementParamSpec(
                ID,
                (ECPrivateKey) keyPair.getPrivate(),
                (ECPublicKey) keyPair.getPublic(),
                ID,
                (ECPublicKey) keyPair.getPublic(),
                true,
                32);
    }

    @Test
    public void testInit() throws Exception {
        ECPrivateKey priKey = TestUtils.privateKey(PRI_KEY);
        ECPublicKey pubKey = TestUtils.publicKey(PUB_KEY);

        SM2KeyAgreementParamSpec paramSpec = new SM2KeyAgreementParamSpec(
                ID,
                priKey,
                pubKey,
                ID,
                pubKey,
                true,
                32);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2", PROVIDER);
        keyAgreement.init(priKey, paramSpec);
    }

    @Test
    public void testInitWithoutParams() throws Exception {
        ECPrivateKey priKey = TestUtils.privateKey(PRI_KEY);
        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2", PROVIDER);
        assertThrows(
                UnsupportedOperationException.class,
                () -> keyAgreement.init(priKey));
    }

    @Test
    public void testDoPhase() throws Exception {
        ECPrivateKey priKey = TestUtils.privateKey(PRI_KEY);
        ECPublicKey pubKey = TestUtils.publicKey(PUB_KEY);

        SM2KeyAgreementParamSpec paramSpec = new SM2KeyAgreementParamSpec(
                ID,
                priKey,
                pubKey,
                ID,
                pubKey,
                true,
                32);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2", PROVIDER);

        assertThrows(
                IllegalStateException.class,
                () -> keyAgreement.doPhase(priKey, true));

        keyAgreement.init(priKey, paramSpec);

        assertThrows(
                InvalidKeyException.class,
                () -> keyAgreement.doPhase(priKey, true));

        assertThrows(
                IllegalStateException.class,
                () -> keyAgreement.doPhase(pubKey, false));

        keyAgreement.doPhase(pubKey, true);

        assertThrows(
                IllegalStateException.class,
                () -> keyAgreement.doPhase(pubKey, true));
    }

    @Test
    public void testGenerateSecret() throws Exception {
        testGenerateSecret(16, toBytes("6C89347354DE2484C60B4AB1FDE4C6E5"));
    }

    @Test
    public void testGenerateSecretWithKeySize() throws Exception {
        testGenerateSecretWithKeySize(7);
        testGenerateSecretWithKeySize(15);
        testGenerateSecretWithKeySize(17);
        testGenerateSecretWithKeySize(32);
        testGenerateSecretWithKeySize(33);
        testGenerateSecretWithKeySize(63);
        testGenerateSecretWithKeySize(64);
        testGenerateSecretWithKeySize(65);
    }

    private void testGenerateSecretWithKeySize(int keySize) throws Exception {
        testGenerateSecret(keySize, null);
    }

    private void testGenerateSecret(int keySize, byte[] expectedSharedKey)
            throws Exception {
        String idHex = "31323334353637383132333435363738";
        String priKeyHex = "81EB26E941BB5AF16DF116495F90695272AE2CD63D6C4AE1678418BE48230029";
        String pubKeyHex = "04160E12897DF4EDB61DD812FEB96748FBD3CCF4FFE26AA6F6DB9540AF49C942324A7DAD08BB9A459531694BEB20AA489D6649975E1BFCF8C4741B78B4B223007F";
        String tmpPriKeyHex = "D4DE15474DB74D06491C440D305E012400990F3E390C7E87153C12DB2EA60BB3";
        String tmpPubKeyHex = "0464CED1BDBC99D590049B434D0FD73428CF608A5DB8FE5CE07F15026940BAE40E376629C7AB21E7DB260922499DDB118F07CE8EAAE3E7720AFEF6A5CC062070C0";

        String peerIdHex = "31323334353637383132333435363738";
        String peerPriKeyHex = "785129917D45A9EA5437A59356B82338EAADDA6CEB199088F14AE10DEFA229B5";
        String peerPubKeyHex = "046AE848C57C53C7B1B5FA99EB2286AF078BA64C64591B8B566F7357D576F16DFBEE489D771621A27B36C5C7992062E9CD09A9264386F3FBEA54DFF69305621C4D";
        String peerTmpPriKeyHex = "7E07124814B309489125EAED101113164EBF0F3458C5BD88335C1F9D596243D6";
        String peerTmpPubKeyHex = "04ACC27688A6F7B706098BC91FF3AD1BFF7DC2802CDB14CCCCDB0A90471F9BD7072FEDAC0494B2FFC4D6853876C79B8F301C6573AD0AA50F39FC87181E1A1B46FE";

        // Generate shared secret by the local endpoint
        SM2KeyAgreementParamSpec paramSpec = new SM2KeyAgreementParamSpec(
                toBytes(idHex),
                TestUtils.privateKey(priKeyHex),
                TestUtils.publicKey(pubKeyHex),
                toBytes(peerIdHex),
                TestUtils.publicKey(peerPubKeyHex),
                true,
                keySize);
        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2", PROVIDER);
        keyAgreement.init(TestUtils.privateKey(tmpPriKeyHex), paramSpec);
        keyAgreement.doPhase(TestUtils.publicKey(peerTmpPubKeyHex), true);
        SecretKey sharedKey = keyAgreement.generateSecret("SM2SharedSecret");

        assertEquals(keySize, sharedKey.getEncoded().length);
        if (expectedSharedKey != null) {
            assertArrayEquals(expectedSharedKey, sharedKey.getEncoded());
        }

        // Generate shared secret by the remote endpoint
        SM2KeyAgreementParamSpec peerParamSpec = new SM2KeyAgreementParamSpec(
                toBytes(peerIdHex),
                TestUtils.privateKey(peerPriKeyHex),
                TestUtils.publicKey(peerPubKeyHex),
                toBytes(idHex),
                TestUtils.publicKey(pubKeyHex),
                false,
                keySize);
        KeyAgreement peerKeyAgreement = KeyAgreement.getInstance("SM2", PROVIDER);
        peerKeyAgreement.init(TestUtils.privateKey(peerTmpPriKeyHex), peerParamSpec);
        peerKeyAgreement.doPhase(TestUtils.publicKey(tmpPubKeyHex), true);
        SecretKey peerSharedKey = peerKeyAgreement.generateSecret("SM2SharedSecret");

        assertArrayEquals(sharedKey.getEncoded(), peerSharedKey.getEncoded());
    }

    @Test
    public void testReuseKeyAgreement() throws Exception {
        ECPrivateKey priKey = TestUtils.privateKey(PRI_KEY);
        ECPublicKey pubKey = TestUtils.publicKey(PUB_KEY);

        SM2KeyAgreementParamSpec paramSpec = new SM2KeyAgreementParamSpec(
                ID,
                priKey,
                pubKey,
                ID,
                pubKey,
                true,
                32);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2", PROVIDER);

        keyAgreement.init(priKey, paramSpec);
        keyAgreement.doPhase(pubKey, true);
        keyAgreement.generateSecret();

        // Reuse the keyAgreement
        keyAgreement.init(priKey, paramSpec);
        keyAgreement.doPhase(pubKey, true);
        keyAgreement.generateSecret();
    }

    @Test
    public void testGenerateSecretWithNoneSM2PubKey() throws Exception {
        KeyPairGenerator sm2kpg = KeyPairGenerator.getInstance("SM2", PROVIDER);
        KeyPair sm2KeyPair = sm2kpg.generateKeyPair();
        KeyPair sm2EKeyPair = sm2kpg.generateKeyPair();

        // SECP256R1
        KeyPairGenerator eckpg = KeyPairGenerator.getInstance("EC");
        eckpg.initialize(256);
        KeyPair ecKeyPair = eckpg.generateKeyPair();
        KeyPair ecEKeyPair = eckpg.generateKeyPair();

        SM2KeyAgreementParamSpec paramSpec = new SM2KeyAgreementParamSpec(
                ID,
                (ECPrivateKey) sm2KeyPair.getPrivate(),
                (ECPublicKey) sm2KeyPair.getPublic(),
                ID,
                (ECPublicKey) ecKeyPair.getPublic(),
                true,
                32);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2", PROVIDER);

        keyAgreement.init(sm2EKeyPair.getPrivate(), paramSpec);
        assertThrows(InvalidKeyException.class,
                () -> keyAgreement.doPhase(ecEKeyPair.getPublic(), true));
    }

    @Test
    public void testKeyRange() throws Exception {
        // privateKey = order - 1
        testKeyRange(1);

        // privateKey = order
        assertThrows(IllegalArgumentException.class, () -> testKeyRange(0));

        // privateKey = order + 1
        assertThrows(InvalidKeyException.class, () -> testKeyRange(-1));
    }

    // orderOffset: the relative offset to the order
    private void testKeyRange(int orderOffset) throws Exception {
        ECPrivateKey priKey = TestUtils.privateKey(PRI_KEY);
        ECPublicKey pubKey = TestUtils.publicKey(PUB_KEY);
        SM2KeyAgreementParamSpec paramSpec = new SM2KeyAgreementParamSpec(
                ID,
                priKey,
                pubKey,
                ID,
                pubKey,
                true,
                32);

        KeyPair keyPair = keyPair(orderOffset);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2", PROVIDER);
        keyAgreement.init(keyPair.getPrivate(), paramSpec);
        keyAgreement.doPhase(keyPair.getPublic(), true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        assertEquals(32, sharedSecret.length);
    }

    private static KeyPair keyPair(int orderOffset) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2");

        BigInteger privateKeyS = ECOperator.SM2.getOrder().subtract(
                BigInteger.valueOf(orderOffset));
        ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(
                new SM2PrivateKeySpec(privateKeyS.toByteArray()));

        ECPoint publicPoint = ECOperator.SM2.multiply(privateKeyS);
        ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(
                new SM2PublicKeySpec(publicPoint));

        return new KeyPair(publicKey, privateKey);
    }
}
