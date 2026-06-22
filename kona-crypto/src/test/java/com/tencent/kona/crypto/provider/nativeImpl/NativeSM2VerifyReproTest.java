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

import com.tencent.kona.crypto.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import static com.tencent.kona.crypto.CryptoUtils.copy;
import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.provider.nativeImpl.NativeCrypto.OPENSSL_FAILURE;
import static com.tencent.kona.crypto.util.Constants.*;

/**
 * Reproduces the native verify defect: the OpenSSL/Tongsuo verify APIs return
 * {@code 1} for success, {@code 0} for an invalid signature, and a negative
 * value on internal error. The JNI layer coerces "non-zero -> success"
 * ({@code !EVP_DigestVerifyFinal(...)} and {@code verify_status ? SUCCESS :
 * FAILURE}), so a negative error code is wrongly reported as a successful
 * verification.
 *
 * <p>A DER-encoded SM2 signature with {@code r = 0} and {@code s = 0} drives
 * Tongsuo's {@code sm2_sig_verify} to return {@code -1}, which the current code
 * turns into a successful verification of a forged signature. These tests
 * assert the correct behaviour (such a signature MUST be rejected) and
 * therefore FAIL against the buggy code and PASS once the JNI layer compares
 * strictly against {@code 1}.
 */
@EnabledOnOs(OS.LINUX)
public class NativeSM2VerifyReproTest {

    private static final byte[] ID
            = toBytes("31323334353637383132333435363738");
    private static final byte[] MESSAGE = "message".getBytes();

    // A structurally valid DER ECDSA-Sig-Value with both integers being the
    // 32-byte zero value: SEQUENCE { INTEGER 0, INTEGER 0 }.
    // 30 44 02 20 00..00(32) 02 20 00..00(32)
    private static final byte[] FORGED_ZERO_SIG = toBytes(
            "3044"
          + "0220" + "0000000000000000000000000000000000000000000000000000000000000000"
          + "0220" + "0000000000000000000000000000000000000000000000000000000000000000");

    /**
     * Sanity check: a genuine signature must still verify, so the test setup
     * itself is sound.
     */
    @Test
    public void testGenuineSignatureStillVerifies() {
        try (NativeSM2KeyPairGen gen = new NativeSM2KeyPairGen()) {
            byte[] keyPair = gen.genKeyPair();
            byte[] priKey = copy(keyPair, 0, SM2_PRIKEY_LEN);
            byte[] pubKey = copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

            byte[] sig = NativeCrypto.sm2OneShotSignatureSign(priKey, ID, MESSAGE);
            int verified = NativeCrypto.sm2OneShotSignatureVerify(
                    pubKey, ID, MESSAGE, sig);

            Assertions.assertEquals(NativeCrypto.OPENSSL_SUCCESS, verified,
                    "A genuine signature should verify");
        }
    }

    /**
     * Reproduces the bug on the one-shot native path: a forged r=0/s=0
     * signature must NOT be accepted. The native verify returns a negative
     * error code that the buggy code reports as OPENSSL_SUCCESS(1).
     */
    @Test
    public void testForgedZeroSignatureRejected_oneShot() {
        try (NativeSM2KeyPairGen gen = new NativeSM2KeyPairGen()) {
            byte[] keyPair = gen.genKeyPair();
            byte[] pubKey = copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

            int verified = NativeCrypto.sm2OneShotSignatureVerify(
                    pubKey, ID, MESSAGE, FORGED_ZERO_SIG);

            Assertions.assertEquals(OPENSSL_FAILURE, verified,
                    "A forged r=0/s=0 signature must be rejected, but the "
                  + "native verify returned " + verified
                  + " (negative error code coerced to success)");
        }
    }

    /**
     * Reproduces the bug on the stateful native path via the higher-level
     * {@link NativeSM2Signature} wrapper, mirroring real Provider usage.
     */
    @Test
    public void testForgedZeroSignatureRejected_stateful() throws Exception {
        try (NativeSM2KeyPairGen gen = new NativeSM2KeyPairGen()) {
            byte[] keyPair = gen.genKeyPair();
            byte[] pubKey = copy(keyPair, SM2_PRIKEY_LEN, SM2_PUBKEY_LEN);

            try (NativeSM2Signature verifier
                         = new NativeSM2Signature(pubKey, ID, false)) {
                boolean verified = verifier.verify(MESSAGE, FORGED_ZERO_SIG);

                Assertions.assertFalse(verified,
                        "A forged r=0/s=0 signature must be rejected by "
                      + "NativeSM2Signature.verify()");
            }
        }
    }

    /**
     * The defect must stay fixed under repeated/concurrent use, since the
     * native context is reused across operations.
     */
    @Test
    public void testForgedZeroSignatureRejectedParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testForgedZeroSignatureRejected_oneShot();
            return null;
        });
    }
}
