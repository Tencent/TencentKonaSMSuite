/*
 * Copyright (C) 2022, 2024, Tencent. All rights reserved.
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

package com.tencent.kona.ssl;

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.crypto.KonaCryptoProvider;
import com.tencent.kona.pkix.KonaPKIXProvider;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.StringJoiner;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * The utilities for testing certification and key store.
 */
public class TestUtils {

    public static final String PROVIDER = SSLInsts.PROV_NAME;

    private static final String BEGIN = "-----BEGIN";
    private static final String END = "-----END";

    private static final Path TEST_RES_PATH
            = Paths.get("src/test/resources");

    public static void enableTestDebug() {
        System.setProperty("test.debug", "true");
    }

    public static void enableKonaSSLDebug() {
        System.setProperty("com.tencent.kona.ssl.debug", "all");
    }

    public static void enableJSSEDebug() {
        System.setProperty("javax.net.debug", "all");
    }

    public static void enableDebug() {
        enableTestDebug();
        enableKonaSSLDebug();
        enableJSSEDebug();
    }

    public static void addProviders() {
        Security.addProvider(CryptoInsts.PROV);
        Security.addProvider(KonaPKIXProvider.instance());
        Security.addProvider(KonaSSLProvider.instance());
    }

    public static void insertProvidersAtTop() {
        Security.insertProviderAt(CryptoInsts.PROV, 1);
        Security.insertProviderAt(KonaPKIXProvider.instance(), 2);
        Security.insertProviderAt(KonaSSLProvider.instance(), 3);
    }

    public static Path resFilePath(String resource) {
        return TEST_RES_PATH.resolve(resource);
    }

    public static Path certFilePath(String certDirName, String file) {
        return resFilePath(certDirName + File.separator + file);
    }

    public static Path certFilePath(String file) {
        return certFilePath("certs", file);
    }

    public static String certStr(String certDirName, String certFileName) {
        try {
            return filterPem(Files.readAllLines(
                    certFilePath(certDirName, certFileName)), true);
        } catch (IOException e) {
            throw new RuntimeException("Read file failed", e);
        }
    }

    public static String certStr(String certFileName) {
        return certStr("certs", certFileName);
    }

    public static String crlStr(String crlFileName) {
        return certStr(crlFileName);
    }

    public static String keyStr(String certDirName, String keyFileName) {
        try {
            return filterPem(Files.readAllLines(
                    certFilePath(certDirName, keyFileName)), false);
        } catch (IOException e) {
            throw new RuntimeException("Read file failed", e);
        }
    }

    public static String keyStr(String keyFileName) {
        return keyStr("certs", keyFileName);
    }

    public static byte[] certBytes(String certFileName) {
        try {
            return Files.readAllBytes(certFilePath(certFileName));
        } catch (IOException e) {
            throw new RuntimeException("Read file failed", e);
        }
    }

    public static byte[] crlBytes(String crlFileName) {
        return certBytes(crlFileName);
    }

    public static X509Certificate cert(String certStr)
            throws CertificateException, NoSuchProviderException {
        return cert(certStr, PROVIDER);
    }

    public static X509Certificate certAsFile(String certFileName)
            throws CertificateException, NoSuchProviderException {
        return cert(certStr(certFileName), PROVIDER);
    }

    public static X509CRL crlAsFile(String crlFileName)
            throws CertificateException, NoSuchProviderException, CRLException {
        return crl(crlStr(crlFileName), PROVIDER);
    }

    public static X509Certificate certBC(String certStr)
            throws CertificateException, NoSuchProviderException {
        return cert(certStr, "BC");
    }

    public static X509Certificate certAsFileBC(String certFileName)
            throws CertificateException, NoSuchProviderException {
        return cert(certStr(certFileName), "BC");
    }

    public static X509Certificate cert(String certStr, String provider)
            throws CertificateException, NoSuchProviderException {
        CertificateFactory certFactory
                = CertificateFactory.getInstance("X.509", provider);
        return (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(certStr.getBytes()));
    }

    public static X509CRL crl(String crlStr, String provider)
            throws CertificateException, NoSuchProviderException, CRLException {
        CertificateFactory certFactory
                = CertificateFactory.getInstance("X.509", provider);
        return (X509CRL) certFactory.generateCRL(
                new ByteArrayInputStream(crlStr.getBytes()));
    }

    public static Certificate[] certChain(String... certStrs)
            throws CertificateException, NoSuchProviderException {
        Certificate[] certPath = new Certificate[certStrs.length];
        for (int i = 0; i < certStrs.length; i++) {
            certPath[i] = cert(certStrs[i]);
        }

        return certPath;
    }

    public static Certificate[] certChainAsFiles(String... certFileNames)
            throws CertificateException, NoSuchProviderException {
        String[] certStrs = new String[certFileNames.length];
        for (int i = 0; i < certFileNames.length; i++) {
            certStrs[i] = certStr(certFileNames[i]);
        }

        return certChain(certStrs);
    }

    public static String concatCertFiles(String... fileNames) {
        StringJoiner joiner = new StringJoiner("\n");
        for (String fileName : fileNames) {
            try {
                joiner.add(String.join("\n", Files.readAllLines(certFilePath(fileName))));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return joiner.toString();
    }

    public static RSAPrivateKey rsaPrivateKeyAsFile(String keyFileName)
            throws Exception {
        return (RSAPrivateKey) privateKey(
                "RSA", keyStr(keyFileName), PROVIDER);
    }

    public static ECPrivateKey ecPrivateKeyAsFile(String keyFileName)
            throws Exception {
        return privateKey(keyStr(keyFileName), PROVIDER);
    }

    public static ECPrivateKey ecPrivateKey(String keyPEM)
            throws Exception {
        return privateKey(keyPEM, PROVIDER);
    }

    public static ECPrivateKey privateKeyBC(String keyPEM)
            throws Exception {
        return privateKey(keyPEM, "BC");
    }

    public static ECPrivateKey privateKeyAsFileBC(String keyFileName)
            throws Exception {
        return privateKey(keyStr(keyFileName), "BC");
    }

    private static ECPrivateKey privateKey(
            String keyPEM, String provider) throws Exception {
        return (ECPrivateKey) privateKey("EC", keyPEM, provider);
    }

    private static PrivateKey privateKey(
            String keyAlgo, String keyPEM, String provider) throws Exception {
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                Base64.getMimeDecoder().decode(keyPEM));
        KeyFactory keyFactory = KeyFactory.getInstance(keyAlgo, provider);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    public static PrivateKey encryptedRSAPrivateKeyAsFile(
            String encryptedKeyFileName, String passphrase)
            throws Exception {
        return encryptedPrivateKey(
                "RSA", keyStr(encryptedKeyFileName), passphrase);
    }

    public static PrivateKey encryptedECPrivateKeyAsFile(
            String encryptedKeyFileName, String passphrase)
            throws Exception {
        return encryptedPrivateKey(
                "EC", keyStr(encryptedKeyFileName), passphrase);
    }

    public static PrivateKey encryptedPrivateKey(
            String keyAlg, String encryptedKeyPEM, String passphrase)
            throws Exception {
        EncryptedPrivateKeyInfo encryptedPrivateKeyInfo
                = new EncryptedPrivateKeyInfo(
                        Base64.getMimeDecoder().decode(encryptedKeyPEM));

        // It cannot get SecretKeyFactory by EncryptedPrivateKeyInfo::getAlgName
        // with OID 1.2.840.113549.1.5.13 due to JDK-8226824. So it has to apply
        // the algorithm PBEWithHmacSHA256AndAES_256 explicitly.
        String algorithm = "PBEWithHmacSHA256AndAES_256";
        SecretKeyFactory pbeKeyFactory = SecretKeyFactory.getInstance(algorithm);
        Key pbeKey = pbeKeyFactory.generateSecret(new PBEKeySpec(
                passphrase.toCharArray()));
        Cipher cipher = CryptoInsts.getCipher(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, pbeKey,
                encryptedPrivateKeyInfo.getAlgParameters());
        // Cannot directly get PKCS8EncodedKeySpec due to the changes for
        // EncryptedPrivateKeyInfo::checkPKCS8Encoding on JDK 11+.
//        PKCS8EncodedKeySpec pkcs8EncodedKeySpec =
//                encryptedPrivateKeyInfo.getKeySpec(cipher);
        byte[] encoded = cipher.doFinal(
                encryptedPrivateKeyInfo.getEncryptedData());
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = CryptoInsts.getKeyFactory(keyAlg);
        return keyFactory.generatePrivate(pkcs8KeySpec);
    }

    private static String filterPem(List<String> lines, boolean keepSeparator) {
        StringBuilder result = new StringBuilder();

        boolean begin = false;
        for (String line : lines) {
            if (line.startsWith(END)) {
                if (keepSeparator) {
                    result.append(line);
                }
                break;
            }

            if (line.startsWith(BEGIN)) {
                begin = true;
                if (keepSeparator) {
                    result.append(line).append("\n");
                }
                continue;
            }

            if (begin) {
                result.append(line).append("\n");
            }
        }

        return result.toString();
    }

    /* ***** Key store ***** */

    public static KeyStore trustStore(String[] aliases, String[] certStrs)
            throws KeyStoreException, CertificateException, IOException,
            NoSuchAlgorithmException, NoSuchProviderException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "KonaPKIX");
        keyStore.load(null, null);

        for (int i = 0; i < aliases.length; i++) {
            keyStore.setCertificateEntry(aliases[i], cert(certStrs[i]));
        }

        return keyStore;
    }

    public static KeyStore keyStore(String alias, String keyStr,
            char[] password, String[] certStrs) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "KonaPKIX");;
        keyStore.load(null, null);

        keyStore.setKeyEntry(
                alias,
                ecPrivateKey(keyStr),
                password,
                certChain(certStrs));

        return keyStore;
    }

    public static int getFreePort() {
        try (ServerSocket serverSocket = new ServerSocket(
                0, 5, InetAddress.getLoopbackAddress());) {
            return serverSocket.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException("Get free port failed!", e);
        }
    }

    public static void repeatTaskParallelly(Callable<Void> task, int count)
            throws Exception {
        List<Callable<Void>> tasks = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            tasks.add(task);
        }

        ExecutorService executorService = Executors.newFixedThreadPool(count);
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

    public static void repeatTaskParallelly(Callable<Void> task)
            throws Exception {
        repeatTaskParallelly(task, 100);
    }

    public static void repeatTaskSerially(Callable<Void> task, int count)
            throws Exception {
        for (int i = 0; i < count; i++) {
            task.call();
        }
    }

    public static void repeatTaskSerially(Callable<Void> task)
            throws Exception{
        repeatTaskSerially(task, 200);
    }

    @FunctionalInterface
    public interface Executable {

        void execute() throws Exception;
    }
}
