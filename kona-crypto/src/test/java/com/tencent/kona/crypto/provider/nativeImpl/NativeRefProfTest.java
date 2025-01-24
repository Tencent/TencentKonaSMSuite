/*
 * Copyright (C) 2024, 2025, THL A29 Limited, a Tencent company. All rights reserved.
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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

import static com.tencent.kona.crypto.CryptoUtils.copy;
import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.util.Constants.*;

/**
 * A test for analyzing NativeRef objects, like NativeSM3.
 */
public class NativeRefProfTest {

    private static final byte[] KEY = toBytes("0123456789abcdef0123456789abcdef");
    private static final byte[] IV = toBytes("10000000000000000000000000000001");
    private static final byte[] GCM_IV = toBytes("100000000000000000000003");
    private static final byte[] DATA = toBytes(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    private static final byte[] ID = "012345678012345678".getBytes();

    private static final int ITERATIONS = 1_000_000_000;

    private static void testSM3Digest() {
        for (int i = 0; i < ITERATIONS; i++) {
            NativeSM3 sm3 = new NativeSM3();
            sm3.update(DATA);
            sm3.doFinal(DATA);
            sm3.close();
        }
    }

    private static void testSM3OneShotDigest() {
        for (int i = 0; i < ITERATIONS; i++) {
            NativeCrypto.sm3OneShotDigest(DATA);
        }
    }

    private static void testSM3HMac() {
        for (int i = 0; i < ITERATIONS; i++) {
            NativeSM3HMac sm3HMac = new NativeSM3HMac(KEY);
            sm3HMac.update(DATA);
            sm3HMac.doFinal(DATA);
            sm3HMac.close();
        }
    }

    private static void testSM3OneShotHMac() {
        for (int i = 0; i < ITERATIONS; i++) {
            NativeSM3HMac sm3HMac = new NativeSM3HMac(KEY);
            sm3HMac.update(DATA);
            sm3HMac.doFinal(DATA);
            sm3HMac.close();
        }
    }

    private static void testSM4CBCEncrypter() {
        for (int i = 0; i < ITERATIONS; i++) {
            NativeSM4 sm4 = new NativeSM4.SM4CBC(true, false, KEY, IV);
            sm4.update(DATA);
            sm4.doFinal(DATA);
            sm4.close();
        }
    }

    private static void testSM4CBCDecrypter() {
        for (int i = 0; i < ITERATIONS; i++) {
            NativeSM4 sm4 = new NativeSM4.SM4CBC(false, false, KEY, IV);
            sm4.update(DATA);
            sm4.doFinal(DATA);
            sm4.close();
        }
    }

    private static void testSM4CTREncrypter() {
        for (int i = 0; i < ITERATIONS; i++) {
            NativeSM4 sm4 = new NativeSM4.SM4CTR(true, KEY, IV);
            sm4.update(DATA);
            sm4.doFinal(DATA);
            sm4.close();
        }
    }

    private static void testSM4CTRDecrypter() {
        for (int i = 0; i < ITERATIONS; i++) {
            NativeSM4 sm4 = new NativeSM4.SM4CTR(false, KEY, IV);
            sm4.update(DATA);
            sm4.doFinal(DATA);
            sm4.close();
        }
    }

    private static void testSM4ECBEncrypter() {
        for (int i = 0; i < ITERATIONS; i++) {
            NativeSM4 sm4 = new NativeSM4.SM4ECB(true, false, KEY);
            sm4.update(DATA);
            sm4.doFinal(DATA);
            sm4.close();
        }
    }

    private static void testSM4ECBDecrypter() {
        for (int i = 0; i < ITERATIONS; i++) {
            NativeSM4 sm4 = new NativeSM4.SM4ECB(false, false, KEY);
            sm4.update(DATA);
            sm4.doFinal(DATA);
            sm4.close();
        }
    }

    private static void testSM4GCMEncrypter() {
        for (int i = 0; i < ITERATIONS; i++) {
            NativeSM4 encrypter = new NativeSM4.SM4GCM(true, KEY, GCM_IV);
            encrypter.update(DATA);
            encrypter.doFinal(DATA);
            encrypter.close();
        }
    }

    private static void testSM4GCMDecrypter() {
        NativeSM4 encrypter = new NativeSM4.SM4GCM(true, KEY, GCM_IV);
        byte[] ciphertext = encrypter.doFinal(DATA);
        encrypter.close();

        for (int i = 0; i < ITERATIONS; i++) {
            NativeSM4 decrypter = new NativeSM4.SM4GCM(false, KEY, GCM_IV);
            decrypter.doFinal(ciphertext);
            decrypter.close();
        }
    }

    private static void testSM2KeyPairGen() {
        for (int i = 0; i < ITERATIONS; i++) {
            NativeSM2KeyPairGen sm2 = new NativeSM2KeyPairGen();
            sm2.genKeyPair();
            sm2.close();
        }
    }

    private static void testSM2OneShotKeyPairGen() {
        for (int i = 0; i < ITERATIONS; i++) {
            NativeCrypto.sm2OneShotKeyPairGenGenKeyPair();
        }
    }

    private static void testSM2CipherEncrypter() throws Exception {
        NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen();
        byte[] keyPair = sm2KeyPairGen.genKeyPair();
        sm2KeyPairGen.close();

        for (int i = 0; i < ITERATIONS; i++) {
            NativeSM2Cipher sm2Encrypter = new NativeSM2Cipher(keyPair);
            sm2Encrypter.encrypt(DATA);
            sm2Encrypter.close();
        }
    }

    private static void testSM2OneShotCipherEncrypter() throws Exception {
        NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen();
        byte[] keyPair = sm2KeyPairGen.genKeyPair();
        sm2KeyPairGen.close();

        for (int i = 0; i < ITERATIONS; i++) {
            NativeCrypto.sm2OneShotCipherEncrypt(keyPair, DATA);
        }
    }

    private static void testSM2CipherDecrypter() throws Exception {
        NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen();
        byte[] keyPair = sm2KeyPairGen.genKeyPair();
        sm2KeyPairGen.close();

        NativeSM2Cipher sm2Encrypter = new NativeSM2Cipher(keyPair);
        byte[] ciphertext = sm2Encrypter.encrypt(DATA);
        sm2Encrypter.close();

        for (int i = 0; i < ITERATIONS; i++) {
            NativeSM2Cipher sm2Decrypter = new NativeSM2Cipher(keyPair);
            sm2Decrypter.decrypt(ciphertext);
            sm2Decrypter.close();
        }
    }

    private static void testSM2OneShotCipherDecrypter() throws Exception {
        NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen();
        byte[] keyPair = sm2KeyPairGen.genKeyPair();
        sm2KeyPairGen.close();

        NativeSM2Cipher sm2Encrypter = new NativeSM2Cipher(keyPair);
        byte[] ciphertext = sm2Encrypter.encrypt(DATA);
        sm2Encrypter.close();

        for (int i = 0; i < ITERATIONS; i++) {
            NativeCrypto.sm2OneShotCipherDecrypt(keyPair, ciphertext);
        }
    }

    private static void testSM2SignatureSign() throws Exception {
        NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen();
        byte[] keyPair = sm2KeyPairGen.genKeyPair();
        byte[] priKey = copy(keyPair, 0, SM2_PRIKEY_LEN);
        byte[] pubKey = copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);
        sm2KeyPairGen.close();

        for (int i = 0; i < ITERATIONS; i++) {
            NativeSM2Signature sm2Signer
                    = new NativeSM2Signature(priKey, pubKey, ID, true);
            sm2Signer.sign(DATA);
            sm2Signer.close();
        }
    }

    private static void testSM2OneShotSignatureSign() throws Exception {
        NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen();
        byte[] keyPair = sm2KeyPairGen.genKeyPair();
        byte[] priKey = copy(keyPair, 0, SM2_PRIKEY_LEN);
        byte[] pubKey = copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);
        sm2KeyPairGen.close();

        for (int i = 0; i < ITERATIONS; i++) {
            NativeCrypto.sm2OneShotSignatureSign(keyPair, priKey, pubKey);
        }
    }

    private static void testSM2SignatureVerify() throws Exception {
        NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen();
        byte[] keyPair = sm2KeyPairGen.genKeyPair();
        sm2KeyPairGen.close();
        byte[] priKey = copy(keyPair, 0, SM2_PRIKEY_LEN);
        byte[] pubKey = copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

        NativeSM2Signature sm2Signer
                = new NativeSM2Signature(priKey, pubKey, ID, true);
        byte[] signature = sm2Signer.sign(DATA);

        for (int i = 0; i < ITERATIONS; i++) {
            NativeSM2Signature sm2Verifier
                    = new NativeSM2Signature(pubKey, ID, false);
            sm2Verifier.verify(DATA, signature);
            sm2Verifier.close();
        }
    }

    private static void testSM2OneShotSignatureVerify() throws Exception {
        NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen();
        byte[] keyPair = sm2KeyPairGen.genKeyPair();
        sm2KeyPairGen.close();
        byte[] priKey = copy(keyPair, 0, SM2_PRIKEY_LEN);
        byte[] pubKey = copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

        NativeSM2Signature sm2Signer
                = new NativeSM2Signature(priKey, pubKey, ID, true);
        byte[] signature = sm2Signer.sign(DATA);

        for (int i = 0; i < ITERATIONS; i++) {
            NativeCrypto.sm2OneShotSignatureVerify(keyPair, priKey, pubKey, signature);
        }
    }

    private static void testSM2KeyAgreement() throws Exception {
        NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen();
        byte[] keyPair = sm2KeyPairGen.genKeyPair();
        byte[] priKey = copy(keyPair, 0, SM2_PRIKEY_LEN);
        byte[] pubKey = copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

        byte[] eKeyPair = sm2KeyPairGen.genKeyPair();
        byte[] ePriKey = copy(eKeyPair, 0, SM2_PRIKEY_LEN);

        byte[] peerKeyPair = sm2KeyPairGen.genKeyPair();
        byte[] peerPubKey = copy(peerKeyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

        byte[] peerEKeyPair = sm2KeyPairGen.genKeyPair();
        byte[] peerEPubKey = copy(peerEKeyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);
        sm2KeyPairGen.close();

        for (int i = 0; i < ITERATIONS; i++) {
            NativeSM2KeyAgreement sm2KeyAgreement = new NativeSM2KeyAgreement();
            sm2KeyAgreement.deriveKey(
                    priKey, pubKey, ePriKey, ID,
                    peerPubKey, peerEPubKey, ID,
                    true, 32);
            sm2KeyAgreement.close();
        }
    }

    private static void testSM2OneShotKeyAgreement() throws Exception {
        NativeSM2KeyPairGen sm2KeyPairGen = new NativeSM2KeyPairGen();
        byte[] keyPair = sm2KeyPairGen.genKeyPair();
        byte[] priKey = copy(keyPair, 0, SM2_PRIKEY_LEN);
        byte[] pubKey = copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

        byte[] eKeyPair = sm2KeyPairGen.genKeyPair();
        byte[] ePriKey = copy(eKeyPair, 0, SM2_PRIKEY_LEN);

        byte[] peerKeyPair = sm2KeyPairGen.genKeyPair();
        byte[] peerPubKey = copy(peerKeyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

        byte[] peerEKeyPair = sm2KeyPairGen.genKeyPair();
        byte[] peerEPubKey = copy(peerEKeyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);
        sm2KeyPairGen.close();

        for (int i = 0; i < ITERATIONS; i++) {
            NativeCrypto.sm2OneShotDeriveKey(
                    priKey, pubKey, ePriKey, ID,
                    peerPubKey, peerEPubKey, ID,
                    true, 32);
        }
    }

    private static void testECKeyPairGenGenKeyPair(int curveNID) {
        for (int i = 0; i < ITERATIONS; i++) {
            NativeECKeyPairGen keyPairGen = new NativeECKeyPairGen(curveNID);
            keyPairGen.genKeyPair();
            keyPairGen.close();
        }
    }

    private static void testECKeyPairGenOneShotGenKeyPair(int curveNID) {
        for (int i = 0; i < ITERATIONS; i++) {
            NativeCrypto.ecOneShotKeyPairGenGenKeyPair(curveNID);
        }
    }

    public static void main(String[] args) throws Exception {
        List<Callable<Void>> tasks = new ArrayList<>();

        tasks.add(()-> {testSM3Digest(); return null;});
        tasks.add(()-> {testSM3OneShotDigest(); return null;});

        tasks.add(()-> {testSM3HMac(); return null;});
        tasks.add(()-> {testSM3OneShotHMac(); return null;});

        tasks.add(()-> {testSM4CBCEncrypter(); return null;});
        tasks.add(()-> {testSM4CBCDecrypter(); return null;});

        tasks.add(()-> {testSM4CTREncrypter(); return null;});
        tasks.add(()-> {testSM4CTRDecrypter(); return null;});

        tasks.add(()-> {testSM4ECBEncrypter(); return null;});
        tasks.add(()-> {testSM4ECBDecrypter(); return null;});

        tasks.add(()-> {testSM4GCMEncrypter(); return null;});
        tasks.add(()-> {testSM4GCMDecrypter(); return null;});

        tasks.add(()-> {testSM2KeyPairGen(); return null;});
        tasks.add(()-> {testSM2OneShotKeyPairGen(); return null;});

        tasks.add(()-> {testSM2CipherEncrypter(); return null;});
        tasks.add(()-> {testSM2CipherDecrypter(); return null;});
        tasks.add(()-> {testSM2OneShotCipherEncrypter(); return null;});
        tasks.add(()-> {testSM2OneShotCipherDecrypter(); return null;});

        tasks.add(()-> {testSM2SignatureSign(); return null;});
        tasks.add(()-> {testSM2SignatureVerify(); return null;});
        tasks.add(()-> {testSM2OneShotSignatureSign(); return null;});
        tasks.add(()-> {testSM2OneShotSignatureVerify(); return null;});

        tasks.add(()-> {testSM2KeyAgreement(); return null;});
        tasks.add(()-> {testSM2OneShotKeyAgreement(); return null;});

        tasks.add(()-> {testECKeyPairGenGenKeyPair(NID_SPEC256R1); return null;});
        tasks.add(()-> {testECKeyPairGenGenKeyPair(NID_SPEC384R1); return null;});
        tasks.add(()-> {testECKeyPairGenGenKeyPair(NID_SPEC521R1); return null;});
        tasks.add(()-> {testECKeyPairGenGenKeyPair(NID_CURVESM2); return null;});

        tasks.add(()-> {testECKeyPairGenOneShotGenKeyPair(NID_SPEC256R1); return null;});
        tasks.add(()-> {testECKeyPairGenOneShotGenKeyPair(NID_SPEC384R1); return null;});
        tasks.add(()-> {testECKeyPairGenOneShotGenKeyPair(NID_SPEC521R1); return null;});
        tasks.add(()-> {testECKeyPairGenOneShotGenKeyPair(NID_CURVESM2); return null;});

        execTasksParallelly(tasks);
    }

    private static void execTasksParallelly(List<Callable<Void>> tasks) throws Exception {
        ExecutorService executorService = Executors.newFixedThreadPool(tasks.size());
        try {
            List<Future<Void>> futures = executorService.invokeAll(tasks);
            futures.forEach(future -> {
                try {
                    future.get();
                } catch (InterruptedException | ExecutionException e) {
                    throw new RuntimeException("Run task failed", e);
                }
            });
        } finally {
            executorService.shutdown();
        }
    }
}
