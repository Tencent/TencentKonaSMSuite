/*
 * Copyright (C) 2023, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. THL A29 Limited designates
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

package com.tencent.kona.pkix.tool;

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.crypto.KonaCryptoProvider;
import com.tencent.kona.javax.crypto.EncryptedPrivateKeyInfo;
import com.tencent.kona.pkix.KonaPKIXProvider;
import com.tencent.kona.pkix.PKIXInsts;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * The tool for creating key store files.
 */
public class KeyStoreTool {

    static {
        Security.addProvider(new KonaCryptoProvider());
        Security.addProvider(new KonaPKIXProvider());
    }

    private static final String BEGIN_KEY = "BEGIN PRIVATE KEY";
    private static final String END_KEY= "END PRIVATE KEY";

    private static final String BEGIN_ENC_KEY = "BEGIN ENCRYPTED PRIVATE KEY";
    private static final String END_ENC_KEY= "END ENCRYPTED PRIVATE KEY";

    private static final String BEGIN_CERT = "BEGIN CERTIFICATE";
    private static final String END_CERT = "END CERTIFICATE";

    static class Arguments {

        private static final String HINT =
                "KeyStoreTool is a handy utility for creating key store with the existing keys and certificates.\n" +
                "For creating new keys and certificates, please use KeyTool.\n\n" +
                "Usages:\n" +
                "  -type        Store type, PKCS12 or JKS. PKCS12 is the default.\n" +
                "  -alias       One or multiple aliases, separated by comma, like alias1,alias2,alieas3.\n" +
                "  -keyAlgo     Private key algorithm, like EC or RSA.\n" +
                "  -key         A PEM file containing a PKCS#8 private key.\n" +
                "  -keyPasswd   Private key password.\n" +
                "               This password is used to encrypt the private key when put it into the keystore.\n" +
                "               If the passed private key is encrypted, this password is also used to decrypt it.\n" +
                "  -certs       A PEM file containing trust certificates or certificate chain.\n" +
                "  -store       Store file path.\n" +
                "  -storePasswd Keystore file password.";

        String type = "PKCS12";
        String[] alias;
        String keyAlgo;
        String key;
        char[] keyPasswd;
        String certs;
        String store;
        char[] storePasswd;

        Arguments(String[] args) {
            for (int i = 0; i < args.length; i += 2) {
                String option = args[i].trim().toLowerCase(Locale.ROOT);
                String value = args[i + 1];
                switch (option) {
                    case "-type":
                        type = value;
                        break;
                    case "-alias":
                        alias = value.split(",");
                        break;
                    case "-keyalgo":
                        keyAlgo = value;
                        break;
                    case "-key":
                        key = value;
                        break;
                    case "-keypasswd":
                        keyPasswd = value.toCharArray();
                        break;
                    case "-certs":
                        certs = value;
                        break;
                    case "-store":
                        store = value;
                        break;
                    case "-storepasswd":
                        storePasswd = value.toCharArray();
                        break;
                }
            }
        }

        // key store.
        private boolean isKeyStore() {
            return keyAlgo != null && key != null && keyPasswd != null;
        }
    }

    public static void main(String[] args) throws Exception {
        if (args == null || args.length == 0 || args.length % 2 != 0) {
            System.out.println(Arguments.HINT);
            return;
        }

        Arguments arguments = new Arguments(args);
        try {
            if (arguments.isKeyStore()) {
                createKeyStore(arguments);
            } else {
                createTrustStore(arguments);
            }
        } finally {
            cleanPasswd(arguments.keyPasswd);
            cleanPasswd(arguments.storePasswd);
        }
    }

    private static void cleanPasswd(char[] passwd) {
        if (passwd != null) {
            Arrays.fill(passwd, ' ');
        }
    }

    private static void createTrustStore(Arguments arguments)
            throws IOException, CertificateException, KeyStoreException,
            NoSuchAlgorithmException {
        KeyStore store = loadStore(arguments.type, arguments.store,
                arguments.storePasswd);

        List<X509Certificate> certs = certs(arguments);
        for (int i = 0, size = certs.size(); i < size; i ++) {
            store.setCertificateEntry(
                    arguments.alias[i].trim(), certs.get(i));
        }

        saveStore(store, arguments.store, arguments.storePasswd);
    }

    private static void createKeyStore(Arguments arguments)
            throws IOException, CertificateException, KeyStoreException,
            NoSuchAlgorithmException, InvalidKeySpecException,
            InvalidAlgorithmParameterException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        KeyStore store = loadStore(arguments.type, arguments.store,
                arguments.storePasswd);

        PrivateKey key = key(arguments);
        List<X509Certificate> certChain = certs(arguments);
        store.setKeyEntry(arguments.alias[0], key,
                arguments.keyPasswd,
                certChain.toArray(new X509Certificate[0]));

        saveStore(store, arguments.store, arguments.storePasswd);
    }

    private static KeyStore loadStore(String type, String storePath,
            char[] storePasswd) throws IOException, CertificateException,
            KeyStoreException, NoSuchAlgorithmException {
        KeyStore store = PKIXInsts.getKeyStore(type);

        if (Files.exists(Paths.get(storePath))) {
            try (InputStream in = new FileInputStream(storePath)) {
                store.load(in, storePasswd);
            }
        } else {
            store.load(null, null);
        }

        return store;
    }

    private static void saveStore(KeyStore store, String storePath,
            char[] storePasswd) throws IOException, CertificateException,
            KeyStoreException, NoSuchAlgorithmException {
        try (OutputStream out = new FileOutputStream(storePath)) {
            store.store(out, storePasswd);
        }
    }

    private static PrivateKey key(Arguments arguments)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
            InvalidAlgorithmParameterException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        try(BufferedReader keyReader = new BufferedReader(
                new FileReader(arguments.key))) {

            PrivateKey key = null;
            StringBuilder keyPem = new StringBuilder();
            String line = keyReader.readLine();
            boolean begin = false;
            while (line != null) {
                if (line.contains(BEGIN_KEY) || line.contains(BEGIN_ENC_KEY)) {
                    begin = true;
                } else if (line.contains(END_KEY) || line.contains(END_ENC_KEY)) {
                    key = key(arguments.keyAlgo, keyPem.toString(),
                            line.contains(END_ENC_KEY) ? arguments.keyPasswd : null);
                    break;
                } else if (begin) {
                    keyPem.append(line).append("\n");
                }

                line = keyReader.readLine();
            }
            return key;
        }
    }

    private static List<X509Certificate> certs(Arguments arguments)
            throws IOException, CertificateException {
        List<X509Certificate> certChain = new ArrayList<>();
        try(BufferedReader certsReader = new BufferedReader(
                new FileReader(arguments.certs))) {
            StringBuilder certPem = new StringBuilder();
            String certLine = certsReader.readLine();
            boolean certBegin = false;
            while (certLine != null) {
                if (certLine.contains(BEGIN_CERT)) {
                    certPem.append(certLine).append("\n");
                    certBegin = true;
                } else if (certLine.contains(END_CERT)) {
                    certPem.append(certLine);

                    X509Certificate cert = cert(certPem.toString());
                    certChain.add(cert);

                    certBegin = false;
                    certPem = new StringBuilder();
                } else if (certBegin) {
                    certPem.append(certLine).append("\n");
                }

                certLine = certsReader.readLine();
            }
            return certChain;
        }
    }

    private static X509Certificate cert(String certPEM) throws CertificateException {
        CertificateFactory certFactory = PKIXInsts.getCertificateFactory("X.509");
        return (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(certPEM.getBytes(StandardCharsets.UTF_8)));
    }

    private static PrivateKey key(String keyAlg, String keyPEM, char[] keyPasswd)
            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        byte[] encoded = Base64.getMimeDecoder().decode(keyPEM);

        if (keyPasswd != null) {
            EncryptedPrivateKeyInfo encryptedPrivateKeyInfo
                = new EncryptedPrivateKeyInfo(encoded);
            String pbeAlg = encryptedPrivateKeyInfo.getAlgName();
            AlgorithmParameters params = encryptedPrivateKeyInfo.getAlgParameters();

            SecretKeyFactory pbeKeyFactory = SecretKeyFactory.getInstance(pbeAlg);
            Key pbeKey = pbeKeyFactory.generateSecret(new PBEKeySpec(keyPasswd));
            Cipher cipher = CryptoInsts.getCipher(pbeAlg);
            cipher.init(Cipher.DECRYPT_MODE, pbeKey, params);
            // Cannot directly get PKCS8EncodedKeySpec due to the changes for
            // EncryptedPrivateKeyInfo::checkPKCS8Encoding on JDK 11+.
//            PKCS8EncodedKeySpec pkcs8EncodedKeySpec =
//                    encryptedPrivateKeyInfo.getKeySpec(cipher);
            encoded = cipher.doFinal(
                    encryptedPrivateKeyInfo.getEncryptedData());
        }

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = CryptoInsts.getKeyFactory(keyAlg);
        return keyFactory.generatePrivate(privateKeySpec);
    }
}
