/*
 * Copyright (C) 2025, Tencent. All rights reserved.
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

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;

public class KonaECDHKeyAgreementTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testGenerateSecret() throws Exception {
        checkGenerateSecret("secp256r1");
        checkGenerateSecret("secp384r1");
        checkGenerateSecret("secp521r1");
    }

    private void checkGenerateSecret(String curve) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", PROVIDER);
        kpg.initialize(new ECGenParameterSpec(curve));

        KeyPair keyPair = kpg.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        KeyPair peerKeyPair = kpg.generateKeyPair();
        PrivateKey peerPrivateKey = peerKeyPair.getPrivate();
        PublicKey peerPublicKey = peerKeyPair.getPublic();

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", PROVIDER);
        ka.init(privateKey);
        ka.doPhase(peerPublicKey, true);
        byte[] sharedKey = ka.generateSecret();

        KeyAgreement peerKA = KeyAgreement.getInstance("ECDH", PROVIDER);
        peerKA.init(peerPrivateKey);
        peerKA.doPhase(publicKey, true);
        byte[] peerSharedKey = peerKA.generateSecret();

        Assertions.assertNotNull(sharedKey);
        Assertions.assertArrayEquals(sharedKey, peerSharedKey);
    }

    @Test
    public void testParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testGenerateSecret();
            return null;
        });
    }

    @Test
    public void testSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testGenerateSecret();
            return null;
        });
    }
}
