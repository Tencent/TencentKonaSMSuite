/*
 * Copyright (C) 2026, Tencent. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. Tencent designates
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

package com.tencent.kona.pkix;

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.pkix.PKIXUtils.TlcpDualCertPairCheck;
import com.tencent.kona.sun.security.x509.CertificateExtensions;
import com.tencent.kona.sun.security.x509.CertificateSerialNumber;
import com.tencent.kona.sun.security.x509.CertificateValidity;
import com.tencent.kona.sun.security.x509.CertificateVersion;
import com.tencent.kona.sun.security.x509.CertificateX509Key;
import com.tencent.kona.sun.security.x509.KeyUsageExtension;
import com.tencent.kona.sun.security.x509.X500Name;
import com.tencent.kona.sun.security.x509.X509CertImpl;
import com.tencent.kona.sun.security.x509.X509CertInfo;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Tests for the strict TLCP double-certificate role/pairing rules in
 * {@link PKIXUtils}: the role-exclusive keyUsage predicates and the single
 * pairing entry point {@link PKIXUtils#checkTlcpDualCertPair}. Covers the
 * SAME_KEY and DIFFERENT_IDENTITY branches that the on-wire PoC cannot reach
 * (its payloads all fail earlier at the sign-cert keyUsage check).
 */
public class PKIXUtilsTlcpPairTest {

    // keyUsage bit vectors (index: 0 DS, 1 nonRep, 2 keyEnc, 3 dataEnc, 4 keyAgree)
    private static final boolean[] KU_SIGN = ku(0);          // DS only
    private static final boolean[] KU_ENC = ku(2, 3);        // KE + DE
    private static final boolean[] KU_DUAL = ku(0, 2, 3);    // DS + KE + DE
    private static final boolean[] KU_ENC_NONREP = ku(1, 2); // nonRep + KE

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testExclusiveSignCert() throws Exception {
        X509Certificate sign = cert("victim", "victim", newKey().getPublic(), KU_SIGN);
        X509Certificate enc = cert("victim", "victim", newKey().getPublic(), KU_ENC);
        X509Certificate dual = cert("victim", "victim", newKey().getPublic(), KU_DUAL);
        X509Certificate noku = cert("victim", "victim", newKey().getPublic(), null);

        // strict: only a DS-only cert is a sign cert
        Assertions.assertTrue(PKIXUtils.isSignCert(sign, true));
        Assertions.assertFalse(PKIXUtils.isSignCert(enc, true));
        Assertions.assertFalse(PKIXUtils.isSignCert(dual, true));
        Assertions.assertFalse(PKIXUtils.isSignCert(noku, true));
        Assertions.assertFalse(PKIXUtils.isSignCert(null, true));
    }

    @Test
    public void testExclusiveEncCert() throws Exception {
        X509Certificate enc = cert("victim", "victim", newKey().getPublic(), KU_ENC);
        X509Certificate sign = cert("victim", "victim", newKey().getPublic(), KU_SIGN);
        X509Certificate dual = cert("victim", "victim", newKey().getPublic(), KU_DUAL);
        X509Certificate encNonRep = cert("victim", "victim", newKey().getPublic(), KU_ENC_NONREP);
        X509Certificate noku = cert("victim", "victim", newKey().getPublic(), null);

        // strict: only a key-encipherment/agreement cert without signature or
        // non-repudiation usage is an enc cert
        Assertions.assertTrue(PKIXUtils.isEncCert(enc, true));
        Assertions.assertFalse(PKIXUtils.isEncCert(sign, true));
        Assertions.assertFalse(PKIXUtils.isEncCert(dual, true));
        Assertions.assertFalse(PKIXUtils.isEncCert(encNonRep, true)); // nonRepudiation excluded
        Assertions.assertFalse(PKIXUtils.isEncCert(noku, true));
    }

    @Test
    public void testLegacyPredicatesUnchanged() throws Exception {
        X509Certificate noku = cert("victim", "victim", newKey().getPublic(), null);
        X509Certificate dual = cert("victim", "victim", newKey().getPublic(), KU_DUAL);

        // lenient 1-arg behaviour must be unchanged: null keyUsage passes both,
        // a dual-KU cert passes both.
        Assertions.assertTrue(PKIXUtils.isSignCert(noku));
        Assertions.assertTrue(PKIXUtils.isEncCert(noku));
        Assertions.assertTrue(PKIXUtils.isSignCert(dual));
        Assertions.assertTrue(PKIXUtils.isEncCert(dual));
        // the 2-arg lenient form (exclusive=false) delegates to the 1-arg form
        Assertions.assertTrue(PKIXUtils.isSignCert(noku, false));
        Assertions.assertTrue(PKIXUtils.isEncCert(noku, false));
    }

    @Test
    public void testCheckPairOk() throws Exception {
        X509Certificate sign = cert("victim", "ca", newKey().getPublic(), KU_SIGN);
        X509Certificate enc = cert("victim", "ca", newKey().getPublic(), KU_ENC);
        Assertions.assertEquals(TlcpDualCertPairCheck.OK,
                PKIXUtils.checkTlcpDualCertPair(sign, enc));
        Assertions.assertTrue(PKIXUtils.isValidTlcpDualCertPairStrict(sign, enc));
    }

    @Test
    public void testCheckPairSignKeyUsage() throws Exception {
        // slot0 is an enc cert -> fails the sign-cert keyUsage check first
        X509Certificate sign = cert("victim", "ca", newKey().getPublic(), KU_ENC);
        X509Certificate enc = cert("victim", "ca", newKey().getPublic(), KU_ENC);
        Assertions.assertEquals(TlcpDualCertPairCheck.SIGN_KEY_USAGE,
                PKIXUtils.checkTlcpDualCertPair(sign, enc));
    }

    @Test
    public void testCheckPairEncKeyUsage() throws Exception {
        // sign is valid DS-only so we get past the sign check; enc is DS-only
        // (not an enc cert) -> ENC_KEY_USAGE
        X509Certificate sign = cert("victim", "ca", newKey().getPublic(), KU_SIGN);
        X509Certificate enc = cert("victim", "ca", newKey().getPublic(), KU_SIGN);
        Assertions.assertEquals(TlcpDualCertPairCheck.ENC_KEY_USAGE,
                PKIXUtils.checkTlcpDualCertPair(sign, enc));
    }

    @Test
    public void testCheckPairSameKey() throws Exception {
        // same SM2 public key used for both a DS-only and a KE/DE-only cert:
        // both pass the keyUsage checks, then SAME_KEY must fire.
        KeyPair shared = newKey();
        X509Certificate sign = cert("victim", "ca", shared.getPublic(), KU_SIGN);
        X509Certificate enc = cert("victim", "ca", shared.getPublic(), KU_ENC);
        Assertions.assertTrue(PKIXUtils.hasSamePublicKey(sign, enc));
        Assertions.assertEquals(TlcpDualCertPairCheck.SAME_KEY,
                PKIXUtils.checkTlcpDualCertPair(sign, enc));
    }

    @Test
    public void testCheckPairDifferentIdentity() throws Exception {
        // valid sign and enc certs, distinct keys, but different subjects
        X509Certificate sign = cert("attacker", "ca", newKey().getPublic(), KU_SIGN);
        X509Certificate enc = cert("victim", "ca", newKey().getPublic(), KU_ENC);
        Assertions.assertFalse(PKIXUtils.hasSamePublicKey(sign, enc));
        Assertions.assertEquals(TlcpDualCertPairCheck.DIFFERENT_IDENTITY,
                PKIXUtils.checkTlcpDualCertPair(sign, enc));
    }

    @Test
    public void testHasSamePublicKeyNullFailClosed() throws Exception {
        X509Certificate sign = cert("victim", "ca", newKey().getPublic(), KU_SIGN);
        Assertions.assertTrue(PKIXUtils.hasSamePublicKey(sign, null));
        Assertions.assertTrue(PKIXUtils.hasSamePublicKey(null, sign));
        Assertions.assertTrue(PKIXUtils.hasSamePublicKey(null, null));
    }

    // ---- helpers ----

    private static boolean[] ku(int... bits) {
        boolean[] v = new boolean[9];
        for (int b : bits) {
            v[b] = true;
        }
        return v;
    }

    private static KeyPair newKey() throws Exception {
        // Use the crypto provider selected for the current run (Java or native),
        // rather than a hard-coded provider name.
        return CryptoInsts.getKeyPairGenerator("SM2").generateKeyPair();
    }

    // A self-signed SM2 cert with the given subject/issuer CN, public key and
    // keyUsage (null = no keyUsage extension). The cert is signed with a fresh
    // key so that the embedded public key can be chosen independently (needed
    // for the SAME_KEY case).
    private static X509Certificate cert(String subjectCN, String issuerCN,
            PublicKey pub, boolean[] keyUsage) throws Exception {
        PrivateKey signKey = newKey().getPrivate();

        X509CertInfo info = new X509CertInfo();
        info.setVersion(new CertificateVersion(CertificateVersion.V3));
        info.setSerialNumber(
                CertificateSerialNumber.newRandom64bit(new SecureRandom()));
        info.setSubject(new X500Name("CN=" + subjectCN));
        info.setIssuer(new X500Name("CN=" + issuerCN));
        info.setKey(new CertificateX509Key(pub));
        Date from = new Date();
        info.setValidity(new CertificateValidity(
                from, new Date(from.getTime() + 86400_000L)));
        if (keyUsage != null) {
            CertificateExtensions exts = new CertificateExtensions();
            exts.setExtension(
                    KeyUsageExtension.NAME, new KeyUsageExtension(keyUsage));
            info.setExtensions(exts);
        }

        return X509CertImpl.newSigned(info, signKey, "SM3withSM2");
    }
}
