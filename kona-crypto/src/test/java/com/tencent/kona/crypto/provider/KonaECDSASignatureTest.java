/*
 * Copyright (C) 2025, THL A29 Limited, a Tencent company. All rights reserved.
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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import sun.security.ec.SunEC;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.TestUtils.EMPTY;
import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The test for ECDSA signature.
 */
public class KonaECDSASignatureTest {

    private final static byte[] MESSAGE = toBytes(
            "4003607F75BEEE81A027BB6D265BA1499E71D5D7CD8846396E119161A57E01EEB91BF8C9FE");

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testSignature() throws Exception {
        testSignature("SHA1", "secp256r1");
        testSignature("SHA1", "secp384r1");
        testSignature("SHA1", "secp521r1");

        testSignature("SHA224", "secp256r1");
        testSignature("SHA224", "secp384r1");
        testSignature("SHA224", "secp521r1");

        testSignature("SHA256", "secp256r1");
        testSignature("SHA256", "secp384r1");
        testSignature("SHA256", "secp521r1");

        testSignature("SHA384", "secp256r1");
        testSignature("SHA384", "secp384r1");
        testSignature("SHA384", "secp521r1");

        testSignature("SHA512", "secp256r1");
        testSignature("SHA512", "secp384r1");
        testSignature("SHA512", "secp521r1");
    }

    private void testSignature(String md, String curve) throws Exception {
        String provider = PROVIDER.getName();
        testSignature(md, curve, provider, provider);
    }

    @Test
    public void testSignatureWithSunECAsSigner() throws Exception {
        String signerProvider = "SunEC";
        String verifierProvider = PROVIDER.getName();

        testSignature("SHA1", "secp256r1", signerProvider, verifierProvider);
        testSignature("SHA1", "secp384r1", signerProvider, verifierProvider);
        testSignature("SHA1", "secp521r1", signerProvider, verifierProvider);

        testSignature("SHA224", "secp256r1", signerProvider, verifierProvider);
        testSignature("SHA224", "secp384r1", signerProvider, verifierProvider);
        testSignature("SHA224", "secp521r1", signerProvider, verifierProvider);

        testSignature("SHA256", "secp256r1", signerProvider, verifierProvider);
        testSignature("SHA256", "secp384r1", signerProvider, verifierProvider);
        testSignature("SHA256", "secp521r1");

        testSignature("SHA384", "secp256r1", signerProvider, verifierProvider);
        testSignature("SHA384", "secp384r1", signerProvider, verifierProvider);
        testSignature("SHA384", "secp521r1", signerProvider, verifierProvider);

        testSignature("SHA512", "secp256r1", signerProvider, verifierProvider);
        testSignature("SHA512", "secp384r1", signerProvider, verifierProvider);
        testSignature("SHA512", "secp521r1", signerProvider, verifierProvider);
    }

    @Test
    public void testSignatureWithSunECAsVerifier() throws Exception {
        String signerProvider = PROVIDER.getName();
        String verifierProvider = "SunEC";

        testSignature("SHA1", "secp256r1", signerProvider, verifierProvider);
        testSignature("SHA1", "secp384r1", signerProvider, verifierProvider);
        testSignature("SHA1", "secp521r1", signerProvider, verifierProvider);

        testSignature("SHA224", "secp256r1", signerProvider, verifierProvider);
        testSignature("SHA224", "secp384r1", signerProvider, verifierProvider);
        testSignature("SHA224", "secp521r1", signerProvider, verifierProvider);

        testSignature("SHA256", "secp256r1", signerProvider, verifierProvider);
        testSignature("SHA256", "secp384r1", signerProvider, verifierProvider);
        testSignature("SHA256", "secp521r1");

        testSignature("SHA384", "secp256r1", signerProvider, verifierProvider);
        testSignature("SHA384", "secp384r1", signerProvider, verifierProvider);
        testSignature("SHA384", "secp521r1", signerProvider, verifierProvider);

        testSignature("SHA512", "secp256r1", signerProvider, verifierProvider);
        testSignature("SHA512", "secp384r1", signerProvider, verifierProvider);
        testSignature("SHA512", "secp521r1", signerProvider, verifierProvider);
    }

    private void testSignature(String md, String curve,
            String signerProvider, String verifierProvider) throws Exception {
        String sigAlgo = md + "withECDSA";
        KeyPair keyPair = keyPair(curve);
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();

        Signature signer = Signature.getInstance(sigAlgo, signerProvider);
        signer.initSign(priKey);
        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance(sigAlgo, verifierProvider);
        verifier.initVerify(pubKey);
        verifier.update(MESSAGE);
        boolean verified = verifier.verify(signature);

        assertTrue(verified);
    }

    private static KeyPair keyPair(String curve) throws Exception {
        KeyPairGenerator keyPairGen
                = KeyPairGenerator.getInstance("EC", PROVIDER);
        keyPairGen.initialize(new ECGenParameterSpec(curve));
        return keyPairGen.generateKeyPair();
    }

    @Test
    public void testEmptyInput() throws Exception {
        testEmptyInput("SHA1", "secp256r1");
        testEmptyInput("SHA1", "secp384r1");
        testEmptyInput("SHA1", "secp521r1");

        testEmptyInput("SHA224", "secp256r1");
        testEmptyInput("SHA224", "secp384r1");
        testEmptyInput("SHA224", "secp521r1");

        testEmptyInput("SHA256", "secp256r1");
        testEmptyInput("SHA256", "secp384r1");
        testEmptyInput("SHA256", "secp521r1");

        testEmptyInput("SHA384", "secp256r1");
        testEmptyInput("SHA384", "secp384r1");
        testEmptyInput("SHA384", "secp521r1");

        testEmptyInput("SHA512", "secp256r1");
        testEmptyInput("SHA512", "secp384r1");
        testEmptyInput("SHA512", "secp521r1");
    }

    private void testEmptyInput(String md, String curve) throws Exception {
        String sigAlgo = md + "withECDSA";
        KeyPair keyPair = keyPair(curve);
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();

        Signature signer = Signature.getInstance(sigAlgo, PROVIDER);
        signer.initSign(priKey);

        signer.update(EMPTY);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance(sigAlgo, PROVIDER);
        verifier.initVerify(pubKey);
        verifier.update(EMPTY);
        boolean verified = verifier.verify(signature);

        Assertions.assertTrue(verified);
    }

    @Test
    public void testEmptyInputWithByteBuffer() throws Exception {
        testEmptyInputWithByteBuffer("SHA1", "secp256r1");
        testEmptyInputWithByteBuffer("SHA1", "secp384r1");
        testEmptyInputWithByteBuffer("SHA1", "secp521r1");

        testEmptyInputWithByteBuffer("SHA224", "secp256r1");
        testEmptyInputWithByteBuffer("SHA224", "secp384r1");
        testEmptyInputWithByteBuffer("SHA224", "secp521r1");

        testEmptyInputWithByteBuffer("SHA256", "secp256r1");
        testEmptyInputWithByteBuffer("SHA256", "secp384r1");
        testEmptyInputWithByteBuffer("SHA256", "secp521r1");

        testEmptyInputWithByteBuffer("SHA384", "secp256r1");
        testEmptyInputWithByteBuffer("SHA384", "secp384r1");
        testEmptyInputWithByteBuffer("SHA384", "secp521r1");

        testEmptyInputWithByteBuffer("SHA512", "secp256r1");
        testEmptyInputWithByteBuffer("SHA512", "secp384r1");
        testEmptyInputWithByteBuffer("SHA512", "secp521r1");
    }

    private void testEmptyInputWithByteBuffer(String md, String curve)
            throws Exception {
        String sigAlgo = md + "withECDSA";
        KeyPair keyPair = keyPair(curve);
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();

        Signature signer = Signature.getInstance(sigAlgo, PROVIDER);
        signer.initSign(priKey);

        signer.update(ByteBuffer.allocate(0));
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance(sigAlgo, PROVIDER);
        verifier.initVerify(pubKey);
        verifier.update(ByteBuffer.allocate(0));
        boolean verified = verifier.verify(signature);

        Assertions.assertTrue(verified);
    }

    @Test
    public void testNullInput() throws Exception {
        testNullInput("SHA1", "secp256r1");
        testNullInput("SHA1", "secp384r1");
        testNullInput("SHA1", "secp521r1");

        testNullInput("SHA224", "secp256r1");
        testNullInput("SHA224", "secp384r1");
        testNullInput("SHA224", "secp521r1");

        testNullInput("SHA256", "secp256r1");
        testNullInput("SHA256", "secp384r1");
        testNullInput("SHA256", "secp521r1");

        testNullInput("SHA384", "secp256r1");
        testNullInput("SHA384", "secp384r1");
        testNullInput("SHA384", "secp521r1");

        testNullInput("SHA512", "secp256r1");
        testNullInput("SHA512", "secp384r1");
        testNullInput("SHA512", "secp521r1");
    }

    private void testNullInput(String md, String curve) throws Exception {
        String sigAlgo = md + "withECDSA";
        KeyPair keyPair = keyPair(curve);
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();

        Signature signer = Signature.getInstance(sigAlgo, PROVIDER);
        signer.initSign(priKey);
        Assertions.assertThrows(NullPointerException.class,
                () -> signer.update((byte[]) null));

        Signature verifier = Signature.getInstance(sigAlgo, PROVIDER);
        verifier.initVerify(pubKey);
        Assertions.assertThrows(NullPointerException.class,
                () -> verifier.update((byte[]) null));
    }

    @Test
    public void testNullInputWithByteBuffer() throws Exception {
        testNullInputWithByteBuffer("SHA1", "secp256r1");
        testNullInputWithByteBuffer("SHA1", "secp384r1");
        testNullInputWithByteBuffer("SHA1", "secp521r1");

        testNullInputWithByteBuffer("SHA224", "secp256r1");
        testNullInputWithByteBuffer("SHA224", "secp384r1");
        testNullInputWithByteBuffer("SHA224", "secp521r1");

        testNullInputWithByteBuffer("SHA256", "secp256r1");
        testNullInputWithByteBuffer("SHA256", "secp384r1");
        testNullInputWithByteBuffer("SHA256", "secp521r1");

        testNullInputWithByteBuffer("SHA384", "secp256r1");
        testNullInputWithByteBuffer("SHA384", "secp384r1");
        testNullInputWithByteBuffer("SHA384", "secp521r1");

        testNullInputWithByteBuffer("SHA512", "secp256r1");
        testNullInputWithByteBuffer("SHA512", "secp384r1");
        testNullInputWithByteBuffer("SHA512", "secp521r1");
    }

    private void testNullInputWithByteBuffer(String md, String curve)
            throws Exception {
        String sigAlgo = md + "withECDSA";
        KeyPair keyPair = keyPair(curve);
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();

        Signature signer = Signature.getInstance(sigAlgo, PROVIDER);
        signer.initSign(priKey);
        Assertions.assertThrows(NullPointerException.class,
                () -> signer.update((ByteBuffer) null));

        Signature verifier = Signature.getInstance(sigAlgo, PROVIDER);
        verifier.initVerify(pubKey);
        Assertions.assertThrows(NullPointerException.class,
                () -> verifier.update((ByteBuffer) null));
    }

    @Test
    public void testTwice() throws Exception {
        testTwice("SHA1", "secp256r1");
        testTwice("SHA1", "secp384r1");
        testTwice("SHA1", "secp521r1");

        testTwice("SHA224", "secp256r1");
        testTwice("SHA224", "secp384r1");
        testTwice("SHA224", "secp521r1");

        testTwice("SHA256", "secp256r1");
        testTwice("SHA256", "secp384r1");
        testTwice("SHA256", "secp521r1");

        testTwice("SHA384", "secp256r1");
        testTwice("SHA384", "secp384r1");
        testTwice("SHA384", "secp521r1");

        testTwice("SHA512", "secp256r1");
        testTwice("SHA512", "secp384r1");
        testTwice("SHA512", "secp521r1");
    }

    private void testTwice(String md, String curve) throws Exception {
        String sigAlgo = md + "withECDSA";
        KeyPair keyPair = keyPair(curve);
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();

        Signature signer = Signature.getInstance(sigAlgo, PROVIDER);
        signer.initSign(priKey);

        signer.update(MESSAGE, 0, MESSAGE.length / 2);
        signer.update(MESSAGE, MESSAGE.length / 2,
                MESSAGE.length - MESSAGE.length / 2);
        byte[] signature = signer.sign();

        signer.update(MESSAGE);
        signature = signer.sign();

        Signature verifier = Signature.getInstance(sigAlgo, PROVIDER);
        verifier.initVerify(pubKey);

        verifier.update(MESSAGE);
        Assertions.assertTrue(verifier.verify(signature));

        verifier.update(MESSAGE, 0, MESSAGE.length / 2);
        verifier.update(MESSAGE, MESSAGE.length / 2,
                MESSAGE.length - MESSAGE.length / 2);
        Assertions.assertTrue(verifier.verify(signature));
    }

    @Test
    public void testParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testSignature();
            return null;
        });
    }

    @Test
    public void testSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testSignature();
            return null;
        });
    }
}
