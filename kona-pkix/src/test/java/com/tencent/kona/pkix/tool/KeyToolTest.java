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

import com.tencent.kona.pkix.PKIXUtils;
import com.tencent.kona.pkix.TestUtils;
import com.tencent.kona.sun.security.ec.ECOperator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.tencent.kona.sun.security.tools.keytool.Main;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The tests for KeyTool.
 */
public class KeyToolTest {

    private static final Path BASE_DIR = Paths.get("build", "KeyToolTest");

    private static final Path KEYSTORE = path("keystore.ks");

    private static final Path ROOT_KEYSTORE = path("root.ks");
    private static final Path CA_KEYSTORE = path("ca.ks");
    private static final Path EE_KEYSTORE = path("ee.ks");

    private static final String PASSWORD = "testpassword";

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

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
    public void testGenSelfSignedCertOnPKCS12() throws Throwable {
        testGenSelfSignedCertr("PKCS12");
    }

    @Test
    public void testGenSelfSignedCertrOnJKS() throws Throwable {
        testGenSelfSignedCertr("JKS");
    }

    private void testGenSelfSignedCertr(String storeType) throws Throwable {
        genKeyPair(KEYSTORE, storeType, "rsa", "RSA", null, "SHA256withRSA");
        genKeyPair(KEYSTORE, storeType, "ec-secp256r1", "EC", "SECP256R1", "SHA256withECDSA");
        genKeyPair(KEYSTORE, storeType, "ec-sm2", "EC", "curveSM2", "SM3withSM2");

        outputCert(KEYSTORE, storeType, "rsa", null);
        outputCert(KEYSTORE, storeType, "ec-secp256r1", null);
        outputCert(KEYSTORE, storeType, "ec-sm2", null);
    }

    @Test
    public void testGenCSROnPKCS12() throws Throwable {
        testGenCSR("PKCS12");
    }

    @Test
    public void testGenCSROnJKS() throws Throwable {
        testGenCSR("JKS");
    }

    private void testGenCSR(String storeType) throws Throwable {
        genKeyPair(ROOT_KEYSTORE, storeType, "rsa-root", "RSA", null, "SHA256withRSA");
        genKeyPair(ROOT_KEYSTORE, storeType, "ec-secp256r1-root", "EC", "SECP256R1", "SHA256withECDSA");
        genKeyPair(ROOT_KEYSTORE, storeType, "ec-sm2-root", "EC", "curveSM2", "SM3withSM2");

        genCSR(ROOT_KEYSTORE, storeType, "rsa-root", "SHA256withRSA", path("rsa-root.csr"));
        genCSR(ROOT_KEYSTORE, storeType, "ec-secp256r1-root", "SHA256withECDSA", path("ec-secp256r1-root.csr"));
        genCSR(ROOT_KEYSTORE, storeType, "ec-sm2-root", "SM3withSM2", path("ec-sm2-root.csr"));
    }

    @Test
    public void testGenCertChainOnPKCS12() throws Throwable {
        testGenCertChain("PKCS12");
    }

    @Test
    public void testGenCertChainOnJKS() throws Throwable {
        testGenCertChain("JKS");
    }

    @Test
    public void testPBEAlgorithmOnPKCS12() throws Throwable {
        genKeyPair(path("SM3AndSM4.ks"), "PKCS12", "SM3AndSM4",
                "EC", "curveSM2", "SM3withSM2",
                "PBEWithHmacSM3AndSM4", "PBEWithHmacSM3AndSM4", "HmacPBESM3");
        genKeyPair(path("SM3AndSM4-SHA256AndAES.ks"), "PKCS12",
                "SM3AndSM4-SHA256AndAES", "EC", "curveSM2", "SM3withSM2",
                "PBEWithHmacSM3AndSM4", "PBEWithHmacSHA256AndAES_256", "HmacPBESHA256");
        genKeyPair(path("SHA256AndAES.ks"), "PKCS12", "SHA256AndAES",
                "EC", "curveSM2", "SM3withSM2",
                "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA256AndAES_256", "HmacPBESM3");
        genKeyPair(path("SHA256AndAES-SM3AndSM4.ks"), "PKCS12",
                "SHA256AndAES-SM3AndSM4", "EC", "curveSM2", "SM3withSM2",
                "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSM3AndSM4", "HmacPBESM3");
    }

    private void testGenCertChain(String storeType) throws Throwable {
        genCertChain(storeType, "RSA", null, "SHA256withRSA");
        genCertChain(storeType, "EC", "SECP256R1", "SHA256withECDSA");
        genCertChain(storeType, "EC", "curveSM2", "SM3withSM2");
    }

    private void genCertChain(String storeType, String keyAlg, String group,
                              String sigAlg) throws Throwable {
        String suffix = suffix(keyAlg, group, sigAlg);
        String rootAlias = "root-" + suffix;
        String caAlias = "ca-" + suffix;
        String eeAlias = "ee-" + suffix;

        Path caCSRPath = path(caAlias + ".csr");
        Path eeCSRPath = path(eeAlias + ".csr");

        genKeyPair(ROOT_KEYSTORE, storeType, rootAlias, keyAlg, group, sigAlg);
        genKeyPair(CA_KEYSTORE, storeType, caAlias, keyAlg, group, sigAlg);
        genKeyPair(EE_KEYSTORE, storeType, eeAlias, keyAlg, group, sigAlg);

        outputCert(ROOT_KEYSTORE, storeType, rootAlias, path(rootAlias + ".crt"));
        genCSR(CA_KEYSTORE, storeType, caAlias, sigAlg, caCSRPath);

        Path caCertPath = path(caAlias + ".crt");
        genCert(ROOT_KEYSTORE, storeType, rootAlias, sigAlg, caCSRPath, caCertPath);
        checkCert(caCertPath, keyAlg, group, sigAlg);

        genCSR(EE_KEYSTORE, storeType, eeAlias, sigAlg, eeCSRPath);

        Path eeCertPath = path(eeAlias + ".crt");
        genCert(CA_KEYSTORE, storeType, caAlias, sigAlg, eeCSRPath, eeCertPath);
        checkCert(eeCertPath, keyAlg, group, sigAlg);
    }

    private static String suffix(String keyAlg, String group, String sigAlg) {
        StringBuilder suffix = new StringBuilder();
        suffix.append(keyAlg);
        if (group != null) {
            suffix.append("-").append(group);
        }
        suffix.append("-").append(sigAlg);
        return suffix.toString();
    }

    private static void outputCert(Path keystore, String storeType,
            String alias, Path certPath) throws Throwable {
        List<String> args = new ArrayList<>();

        args.add("-v");

        args.add("-exportcert");
        args.add("-rfc");

        args.add("-keystore");
        args.add(keystore.toString());

        args.add("-storetype");
        args.add(storeType);

        args.add("-storepass");
        args.add(PASSWORD);

        args.add("-alias");
        args.add(alias);

        if (certPath != null) {
            args.add("-file");
            args.add(certPath.toString());
        }

        System.out.println("outputCert: " + String.join(" ", args));
        Main.main(args.toArray(new String[0]));
    }

    private static void genKeyPair(Path keystorePath, String storeType,
            String alias, String keyAlg, String group, String sigAlg)
            throws Throwable {
        genKeyPair(keystorePath, storeType, alias, keyAlg, group, sigAlg,
                null, null, null);
    }

    private static void genKeyPair(Path keystorePath, String storeType,
            String alias, String keyAlg, String group, String sigAlg,
            String certPbeAlg, String keyPbeAlg, String macAlg)
            throws Throwable {
        List<String> args = new ArrayList<>();

        args.add("-v");

        args.add("-genkeypair");

        args.add("-keystore");
        args.add(keystorePath.toString());

        args.add("-storetype");
        args.add(storeType);

        args.add("-storepass");
        args.add(PASSWORD);

        args.add("-alias");
        args.add(alias);

        args.add("-keyalg");
        args.add(keyAlg);

        args.add("-keypass");
        args.add(PASSWORD);

        if (group != null) {
            args.add("-groupname");
            args.add(group);
        }

        args.add("-sigalg");
        args.add(sigAlg);

        args.add("-dname");
        args.add("CN=" + alias);

        List<String> jvmOptions = new ArrayList<>();
        if (certPbeAlg != null) {
            jvmOptions.add(
                    "-Dcom.tencent.kona.keystore.pkcs12.certPbeAlgorithm=" + certPbeAlg);
        }
        if (keyPbeAlg != null) {
            jvmOptions.add(
                    "-Dcom.tencent.kona.keystore.pkcs12.keyPbeAlgorithm=" + keyPbeAlg);
        }
        if (macAlg != null) {
            jvmOptions.add(
                    "-Dcom.tencent.kona.keystore.pkcs12.macAlgorithm=" + macAlg);
        }

        System.out.println("genKeyPair: " + String.join(" ", args));
        Main.main(args.toArray(new String[0]));
    }

    private static void genCSR(Path keystorePath, String storeType,
            String alias, String sigAlg, Path csrPath) throws Throwable {
        List<String> args = new ArrayList<>();

        args.add("-v");

        args.add("-certreq");

        args.add("-keystore");
        args.add(keystorePath.toString());

        args.add("-storetype");
        args.add(storeType);

        args.add("-storepass");
        args.add(PASSWORD);

        args.add("-alias");
        args.add(alias);

        args.add("-keypass");
        args.add(PASSWORD);

        args.add("-sigalg");
        args.add(sigAlg);

        if (csrPath != null) {
            args.add("-file");
            args.add(csrPath.toString());
        }

        System.out.println("genCSR: " + String.join(" ", args));
        Main.main(args.toArray(new String[0]));
    }

    private static void genCert(Path keystorePath, String storeType,
            String issuerAlias, String sigAlg , Path csrPath, Path certPath)
            throws Throwable {
        List<String> args = new ArrayList<>();

        args.add("-v");

        args.add("-gencert");
        args.add("-rfc");

        args.add("-keystore");
        args.add(keystorePath.toString());

        args.add("-storetype");
        args.add(storeType);

        args.add("-storepass");
        args.add(PASSWORD);

        args.add("-alias");
        args.add(issuerAlias);

        args.add("-keypass");
        args.add(PASSWORD);

        args.add("-sigalg");
        args.add(sigAlg);

        args.add("-infile");
        args.add(csrPath.toString());

        if (certPath != null) {
            args.add("-outfile");
            args.add(certPath.toString());
        }

        System.out.println("genCert: " + String.join(" ", args));
        Main.main(args.toArray(new String[0]));
    }

    private static void checkCert(Path certPath, String expectedKeyAlg,
            String expectedGroup, String expectedSigAlg) throws Exception {
        X509Certificate cert = PKIXUtils.getCertificate(String.join(
                "\n", Files.readAllLines(certPath)));
        PublicKey publicKey = cert.getPublicKey();
        assertEquals(expectedKeyAlg, publicKey.getAlgorithm());
        if (expectedGroup != null) {
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            BigInteger expectedOrder = null;
            if ("CURVESM2".equalsIgnoreCase(expectedGroup)) {
                expectedOrder = ECOperator.SM2.getOrder();
            } else if ("SECP256R1".equalsIgnoreCase(expectedGroup)) {
                expectedOrder = ECOperator.SECP256R1.getOrder();
            }
            assertEquals(expectedOrder, ecPublicKey.getParams().getOrder());
        }
        assertEquals(expectedSigAlg, cert.getSigAlgName());
    }

    private static Path path(String file) {
        return BASE_DIR.resolve(Paths.get(file));
    }
}
