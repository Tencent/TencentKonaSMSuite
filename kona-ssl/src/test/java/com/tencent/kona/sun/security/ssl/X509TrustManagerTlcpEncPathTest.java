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

package com.tencent.kona.sun.security.ssl;

import com.tencent.kona.pkix.PKIXUtils;
import com.tencent.kona.ssl.TestUtils;
import com.tencent.kona.sun.security.validator.Validator;
import com.tencent.kona.sun.security.validator.ValidatorException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

/**
 * The TLCP enc certificate path validation of the built-in trust manager,
 * for both the PKIX and the SunX509 (Simple) validators.
 *
 * <p>The enc path is the sign certificate's trusted CA path with the leaf
 * replaced by the enc certificate, so no path building takes place.
 */
public class X509TrustManagerTlcpEncPathTest {

    private static final String PKIX = Validator.TYPE_PKIX;
    private static final String SIMPLE = Validator.TYPE_SIMPLE;
    private static final String[] TYPES = { PKIX, SIMPLE };

    @BeforeAll
    public static void setup() throws IOException {
        TestUtils.addProviders();
    }

    private static X509Certificate cert(String dir, String name) {
        try {
            return PKIXUtils.getCertificate(TestUtils.certStr(dir, name));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private static X509Certificate tlcp(String name) {
        return cert("tlcp", name);
    }

    private static X509Certificate neg(String name) {
        return cert("tlcp-enc", name);
    }

    private static X509TrustManagerImpl tm(String type,
            X509Certificate... trusted) {
        return new X509TrustManagerImpl(type, Arrays.asList(trusted));
    }

    private static X509Certificate[] signTrusted(X509TrustManagerImpl tm,
            boolean client) throws CertificateException {
        X509Certificate[] chain = { tlcp("tlcp-server-sign.crt"),
                                    tlcp("tlcp-intca.crt") };
        X509Certificate[] clientChain = { tlcp("tlcp-client-sign.crt"),
                                          tlcp("tlcp-intca.crt") };
        return client
                ? tm.validateClientChain(clientChain, "EC", (Object) null)
                : tm.validateServerChain(chain, "SM2", (Object) null);
    }

    @Test
    public void testGoodEncPath() throws Exception {
        for (String type : TYPES) {
            testGoodEncPathImpl(type);
        }
    }

    private void testGoodEncPathImpl(String type) throws Exception {
        X509TrustManagerImpl tm = tm(type, tlcp("tlcp-ca.crt"));

        X509Certificate enc = tlcp("tlcp-server-enc.crt");
        X509Certificate[] signTrusted = signTrusted(tm, false);
        Assertions.assertEquals(3, signTrusted.length);

        X509Certificate[] encTrusted = tm.validateEncPath(
                signTrusted, enc, false, (Object) null);
        Assertions.assertEquals(3, encTrusted.length);
        Assertions.assertEquals(enc, encTrusted[0]);
        Assertions.assertEquals(signTrusted[1], encTrusted[1]);
        Assertions.assertEquals(signTrusted[2], encTrusted[2]);

        // client direction
        X509Certificate[] clientSignTrusted = signTrusted(tm, true);
        X509Certificate[] clientEncTrusted = tm.validateEncPath(
                clientSignTrusted, tlcp("tlcp-client-enc.crt"), true,
                (Object) null);
        Assertions.assertEquals(3, clientEncTrusted.length);
    }

    @Test
    public void testForgedIssuer() throws Exception {
        for (String type : TYPES) {
            testForgedIssuerImpl(type);
        }
    }

    private void testForgedIssuerImpl(String type) throws Exception {
        X509TrustManagerImpl tm = tm(type, tlcp("tlcp-ca.crt"));
        X509Certificate[] signTrusted = signTrusted(tm, false);

        Assertions.assertThrows(CertificateException.class, () ->
                tm.validateEncPath(signTrusted,
                        neg("server-enc-forged.crt"), false, (Object) null));
    }

    @Test
    public void testExpiredEnc() throws Exception {
        for (String type : TYPES) {
            testExpiredEncImpl(type);
        }
    }

    private void testExpiredEncImpl(String type) throws Exception {
        X509TrustManagerImpl tm = tm(type, tlcp("tlcp-ca.crt"));
        X509Certificate[] signTrusted = signTrusted(tm, false);

        Assertions.assertThrows(CertificateException.class, () ->
                tm.validateEncPath(signTrusted,
                        neg("server-enc-expired.crt"), false, (Object) null));
    }

    @Test
    public void testWrongEku() throws Exception {
        for (String type : TYPES) {
            testWrongEkuImpl(type);
        }
    }

    private void testWrongEkuImpl(String type) throws Exception {
        X509TrustManagerImpl tm = tm(type, tlcp("tlcp-ca.crt"));
        X509Certificate[] signTrusted = signTrusted(tm, false);

        ValidatorException e = Assertions.assertThrows(
                ValidatorException.class, () ->
                        tm.validateEncPath(signTrusted,
                                neg("server-enc-eku.crt"), false, (Object) null));
        Assertions.assertEquals(
                ValidatorException.T_EE_EXTENSIONS, e.getErrorType());
    }

    // A sign certificate cannot be used as the enc certificate.
    @Test
    public void testSignCertAsEnc() throws Exception {
        for (String type : TYPES) {
            testSignCertAsEncImpl(type);
        }
    }

    private void testSignCertAsEncImpl(String type) throws Exception {
        X509TrustManagerImpl tm = tm(type, tlcp("tlcp-ca.crt"));
        X509Certificate[] signTrusted = signTrusted(tm, false);

        for (boolean client : new boolean[] { false, true }) {
            ValidatorException e = Assertions.assertThrows(
                    ValidatorException.class, () ->
                            tm.validateEncPath(signTrusted,
                                    tlcp("tlcp-server-sign.crt"), client,
                                    (Object) null));
            Assertions.assertEquals(
                    ValidatorException.T_EE_EXTENSIONS, e.getErrorType());
        }
    }

    // An enc certificate cannot be used as the sign certificate.
    @Test
    public void testEncCertAsSign() throws Exception {
        for (String type : TYPES) {
            testEncCertAsSignImpl(type);
        }
    }

    private void testEncCertAsSignImpl(String type) {
        X509TrustManagerImpl tm = tm(type, tlcp("tlcp-ca.crt"));
        X509Certificate[] serverChain = { tlcp("tlcp-server-enc.crt"),
                                          tlcp("tlcp-intca.crt") };
        X509Certificate[] clientChain = { tlcp("tlcp-client-enc.crt"),
                                          tlcp("tlcp-intca.crt") };

        Assertions.assertThrows(ValidatorException.class, () ->
                tm.validateServerChain(serverChain, "SM2", (Object) null));
        Assertions.assertThrows(ValidatorException.class, () ->
                tm.validateClientChain(clientChain, "EC", (Object) null));
    }

    // When the leaf is itself a trust anchor, the validators return a
    // one-element chain; the TLCP caller rejects chains shorter than two.
    @Test
    public void testDirectlyTrustedEnc() throws Exception {
        for (String type : TYPES) {
            testDirectlyTrustedEncImpl(type);
        }
    }

    private void testDirectlyTrustedEncImpl(String type) throws Exception {
        X509Certificate enc = tlcp("tlcp-server-enc.crt");
        X509TrustManagerImpl tm = tm(type, tlcp("tlcp-ca.crt"), enc);
        X509Certificate[] signTrusted = signTrusted(tm, false);

        X509Certificate[] encTrusted = tm.validateEncPath(
                signTrusted, enc, false, (Object) null);
        Assertions.assertTrue(encTrusted.length < 2,
                "enc is a trust anchor: " + encTrusted.length);
    }

    @Test
    public void testDirectlyTrustedSign() throws Exception {
        for (String type : TYPES) {
            testDirectlyTrustedSignImpl(type);
        }
    }

    private void testDirectlyTrustedSignImpl(String type) throws Exception {
        X509Certificate sign = tlcp("tlcp-server-sign.crt");
        X509TrustManagerImpl tm = tm(type, tlcp("tlcp-ca.crt"), sign);

        X509Certificate[] signTrusted = signTrusted(tm, false);
        Assertions.assertTrue(signTrusted.length < 2,
                "sign is a trust anchor: " + signTrusted.length);
    }

    @Test
    public void testUntrustedCA() throws Exception {
        for (String type : TYPES) {
            testUntrustedCAImpl(type);
        }
    }

    private void testUntrustedCAImpl(String type) throws Exception {
        X509TrustManagerImpl tm = tm(type, tlcp("tlcp-ca.crt"));
        X509Certificate[] signTrusted = signTrusted(tm, false);

        // The path is rooted at the sign chain's anchor, so a trust manager
        // that does not trust it must not accept the enc certificate.
        X509TrustManagerImpl other = tm(type, neg("server-enc-ca.crt"));
        Assertions.assertThrows(CertificateException.class, () ->
                other.validateEncPath(signTrusted,
                        tlcp("tlcp-server-enc.crt"), false, (Object) null));
    }
}
