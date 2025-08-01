/*
 * Copyright (C) 2023, Tencent. All rights reserved.
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

package com.tencent.kona.pkix.tool;

import com.tencent.kona.pkix.TestUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;

/**
 * The tests for KeyStoreTool.
 */
public class KeyStoreToolTest {

    private static final Path BASE_DIR = Paths.get("build", "KeyStoreToolTest");

    private static final Path TRUST_STORE = path("truststore.ks");
    private static final Path KEY_STORE = path("keystore.ks");
    private static final Path STORE = path("store.ks");

    @BeforeEach
    public void prepare() throws IOException {
        TestUtils.deleteDirIfExists(BASE_DIR);
        Files.createDirectory(BASE_DIR);
    }

    @AfterEach
    public void clean() throws IOException {
        TestUtils.deleteDirIfExists(BASE_DIR);
    }

    @Test
    public void testParseKeyEntryParams() {
        String[] args = new String[] {
                "-alias", "server",
                "-keyAlgo", "EC",
                "-key", "/path/to/key.pem",
                "-keyPasswd", "keyPassword",
                "-certs", "/path/to/certchain.pem",
                "-store", "/path/to/keystore.p12",
                "-storePasswd", "KeystorePassword"};
        KeyStoreTool.Arguments keyEntryArguments
                = new KeyStoreTool.Arguments(args);
        Assertions.assertEquals("server", keyEntryArguments.alias[0]);
        Assertions.assertEquals("EC", keyEntryArguments.keyAlgo);
        Assertions.assertEquals("/path/to/key.pem", keyEntryArguments.key);
        Assertions.assertArrayEquals("keyPassword".toCharArray(), keyEntryArguments.keyPasswd);
        Assertions.assertEquals("/path/to/certchain.pem", keyEntryArguments.certs);
        Assertions.assertEquals("/path/to/keystore.p12", keyEntryArguments.store);
        Assertions.assertArrayEquals("KeystorePassword".toCharArray(),
                keyEntryArguments.storePasswd);
    }

    @Test
    public void testParseTrustEntryParams() {
        String[] args = new String[] {
                "-alias", "trust1,trust2",
                "-certs", "/path/to/trustcerts.pem",
                "-store", "/path/to/truststore.p12",
                "-storePasswd", "TruststorePassword" };
        KeyStoreTool.Arguments trustEntryArgs
                = new KeyStoreTool.Arguments(args);
        Assertions.assertArrayEquals(new String[] {"trust1", "trust2"},
                trustEntryArgs.alias);
        Assertions.assertEquals("/path/to/trustcerts.pem", trustEntryArgs.certs);
        Assertions.assertEquals("/path/to/truststore.p12", trustEntryArgs.store);
        Assertions.assertArrayEquals("TruststorePassword".toCharArray(),
                trustEntryArgs.storePasswd);
    }

    @Test
    public void testCreatePKCS12TrustStore() throws Exception {
        testCreateTrustStore("PKCS12", TRUST_STORE, "truststorepass");
    }

    @Test
    public void testCreateJKSTrustStore() throws Exception {
        testCreateTrustStore("JKS", TRUST_STORE, "truststorepass");
    }

    private void testCreateTrustStore(String type, Path storePath,
            String storePasswd) throws Exception {
        String tlcpCAAlias = "tlcp-ca";
        String rsaCAAlias = "rsa-ca";
        String trustCertsPath = TestUtils.resFilePath("tool/trust_certs.pem").toString();

        String[] args = new String[] {
                "-type", type,
                "-alias", tlcpCAAlias + "," + rsaCAAlias,
                "-certs", trustCertsPath,
                "-store", storePath.toString(),
                "-storePasswd", storePasswd };
        KeyStoreTool.main(args);
        Assertions.assertTrue(Files.exists(storePath));

        KeyStore trustStore = KeyStore.getInstance(type, "KonaPKIX");
        try (InputStream in = new FileInputStream(storePath.toString())) {
            trustStore.load(in, storePasswd.toCharArray());
        }
        Assertions.assertNotNull(trustStore.getCertificate(tlcpCAAlias));
        Assertions.assertNotNull(trustStore.getCertificate(rsaCAAlias));
        Assertions.assertNull(trustStore.getCertificate("x"));
    }

    @Test
    public void testCreatePKCS12KeyStore() throws Exception {
        testCreateKeyStore("PKCS12", KEY_STORE, "keystorepass");
    }

    @Test
    public void testCreateJKSKeyStore() throws Exception {
        testCreateKeyStore("JKS", KEY_STORE, "keystorepass");
    }

    private void testCreateKeyStore(String type, Path storePath,
            String storePasswd) throws Exception {
        String signAlias = "sign";
        String signKeyPath = TestUtils.resFilePath("tool/sign_key.pem").toString();
        String signCertChainPath = TestUtils.resFilePath("tool/sign_cert_chain.pem").toString();

        String encAlias = "enc";
        String encKeyPath = TestUtils.resFilePath("tool/enc_key.pem").toString();
        String encCertChainPath = TestUtils.resFilePath("tool/enc_cert_chain.pem").toString();

        String[] signArgs = new String[] {
                "-type", type,
                "-alias", signAlias,
                "-keyAlgo", "EC",
                "-key", signKeyPath, // This private key is not encrypted
                "-keyPasswd", "signkeypass",
                "-certs", signCertChainPath,
                "-store", storePath.toString(),
                "-storePasswd", storePasswd };
        KeyStoreTool.main(signArgs);

        Assertions.assertTrue(Files.exists(storePath));

        String[] encArgs = new String[] {
                "-type", type,
                "-alias", encAlias,
                "-keyAlgo", "EC",
                "-key", encKeyPath, // This private key is encrypted
                "-keyPasswd", "enckeypass",
                "-certs", encCertChainPath,
                "-store", storePath.toString(),
                "-storePasswd", storePasswd };
        KeyStoreTool.main(encArgs);

        KeyStore trustStore = KeyStore.getInstance(type, "KonaPKIX");
        try (InputStream in = new FileInputStream(storePath.toString())) {
            trustStore.load(in, storePasswd.toCharArray());
        }
        Assertions.assertNotNull(trustStore.getCertificate(signAlias));
        Assertions.assertNotNull(trustStore.getCertificate(encAlias));
    }

    @Test
    public void testCreatePKCS12TrustAndKeyStore() throws Exception {
        testCreateTrustAndKeyStore("PKCS12", STORE);
    }

    @Test
    public void testCreateJKSTrustAndKeyStore() throws Exception {
        testCreateTrustAndKeyStore("JKS", STORE);
    }

    private void testCreateTrustAndKeyStore(String type, Path storePath)
            throws Exception {
        String storePasswd = "storepass";
        testCreateTrustStore(type, storePath, storePasswd);
        testCreateKeyStore(type, storePath, storePasswd);
    }

    private static Path path(String file) {
        return BASE_DIR.resolve(Paths.get(file));
    }
}
