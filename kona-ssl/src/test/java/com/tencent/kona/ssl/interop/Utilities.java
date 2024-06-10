/*
 * Copyright (c) 2020, Oracle and/or its affiliates. All rights reserved.
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
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.tencent.kona.ssl.interop;

import com.tencent.kona.pkix.PKIXUtils;
import com.tencent.kona.ssl.SSLInsts;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.StringJoiner;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/*
 * Utilities for interop testing.
 */
public class Utilities {

    public static final String JAVA_HOME = System.getProperty("java.home");
    public static final String JAVA
            = String.join(File.separator, JAVA_HOME, "bin", "java");
    public static final String JAVA_VERSION = System.getProperty("java.version");

    public static final String CLASSPATH = System.getProperty("test.classpath");

    public static final Charset CHARSET = StandardCharsets.UTF_8;

    public static final boolean DEBUG = Boolean.getBoolean("test.debug");
    public static final int TIMEOUT = Integer.getInteger("test.timeout", 60);
    public static final String LOG_PATH = System.getProperty("test.log.path");

    public static final List<String> JDK11_OPTIONS = Arrays.asList(
            "--add-exports", "java.base/jdk.internal.misc=ALL-UNNAMED");

    public static final List<String> JDK17_OPTIONS = Arrays.asList(
            "--add-exports", "java.base/jdk.internal.access=ALL-UNNAMED");

    public static final String PARAM_DELIMITER = ";";
    public static final String VALUE_DELIMITER = ",";

    public static final char[] PASSWORD = "testpassword".toCharArray();

    /*
     * Gets all supported cipher suites.
     */
    public static CipherSuite[] getAllCipherSuites() {
        String[] supportedCipherSuites;
        try {
            supportedCipherSuites = SSLInsts.getSSLContext("Default")
                    .createSSLEngine()
                    .getSupportedCipherSuites();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(
                    "Failed to get supported cipher suites", e);
        }

        CipherSuite[] cipherSuites = Arrays.stream(supportedCipherSuites)
                .map(CipherSuite::cipherSuite)
                .filter(cipherSuite -> cipherSuite != CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
                .toArray(CipherSuite[]::new);

        return cipherSuites;
    }

    public static SSLContext createSSLContext(Provider provider,
            String kestoreType, String trustManagerAlgorithm, String keyManagerAlgorithm,
            ContextProtocol contextProtocol, CertTuple certTuple) throws Exception {
        String sslProvider = provider == Provider.JDK ? "SunJSSE" : "KonaSSL";
        String keystoreProvider = "KonaPKIX";
        if (provider == Provider.JDK) {
            keystoreProvider = kestoreType.equalsIgnoreCase("JKS")
                    ? "SUN" : "SunJSSE";
        }
        String pkixProvider = provider == Provider.JDK ? "SUN" : "KonaPKIX";

        KeyStore trustStore = createTrustStore(
                kestoreType, keystoreProvider, pkixProvider, certTuple.trustedCerts);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                trustManagerAlgorithm, sslProvider);
        tmf.init(trustStore);

        KeyStore keyStore = createKeyStore(
                keystoreProvider, pkixProvider, certTuple.endEntityCerts);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                keyManagerAlgorithm, sslProvider);
        kmf.init(keyStore, PASSWORD);

        SSLContext context = SSLContext.getInstance(contextProtocol.name, sslProvider);
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return context;
    }

    public static SSLContext createSSLContext(Provider provider,
            ContextProtocol contextProtocol, CertTuple certTuple) throws Exception {
        return createSSLContext(provider,
                KeyStore.getDefaultType(),
                TrustManagerFactory.getDefaultAlgorithm(),
                KeyManagerFactory.getDefaultAlgorithm(),
                contextProtocol, certTuple);
    }

    /*
     * Creates trust store with the specified certificates.
     */
    public static KeyStore createTrustStore(
            String keystoreType, String keystoreProvider, String pkixProvider,
            Cert... certs)
            throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, NoSuchProviderException {
        KeyStore trustStore = KeyStore.getInstance(keystoreType, keystoreProvider);
        trustStore.load(null, null);

        if (certs != null && certs.length > 0) {
            for (int i = 0; i < certs.length; i++) {
                if (certs[i] != null) {
                    trustStore.setCertificateEntry("trust-" + i,
                            createCert(pkixProvider, certs[i]));
                }
            }
        }

        return trustStore;
    }

    /*
     * Creates key store with the specified certificates.
     */
    public static KeyStore createKeyStore(
            String keystoreProvider, String pkixProvider, Cert... certs)
            throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, InvalidKeySpecException,
            NoSuchProviderException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType(), keystoreProvider);
        keyStore.load(null, null);

        if (certs != null && certs.length > 0) {
            X509Certificate lastCert = createCert(pkixProvider, certs[certs.length - 1]);
            if (PKIXUtils.isCA(lastCert)) {
                for (int i = 0; i < certs.length - 1; i++) {
                    String cryptoProvider = cryptoProvider(pkixProvider, certs[i]);
                    if (certs[i] != null) {
                        keyStore.setKeyEntry("cert-" + i, createKey(cryptoProvider, certs[i]), PASSWORD,
                                new Certificate[]{ createCert(pkixProvider, certs[i]), lastCert });
                    }
                }
            } else {
                for (int i = 0; i < certs.length; i++) {
                    if (certs[i] != null) {
                        String cryptoProvider = cryptoProvider(pkixProvider, certs[i]);
                        keyStore.setKeyEntry("cert-" + i, createKey(cryptoProvider, certs[i]), PASSWORD,
                                new Certificate[]{ createCert(pkixProvider, certs[i]) });
                    }
                }
            }
        }

        return keyStore;
    }

    // JDK uses different provider for EC and RSA.
    private static String cryptoProvider(String provider, Cert cert) {
        if (!"SUN".equalsIgnoreCase(provider)) {
            return "KonaCrypto";
        }

        if("RSA".equalsIgnoreCase(cert.keyAlgo.name)) {
            return "SunRsaSign";
        } else if("EC".equalsIgnoreCase(cert.keyAlgo.name)) {
            return "SunEC";
        } else {
           throw new IllegalArgumentException(
                   "Unexpected key algorithm: " + cert.keyAlgo.name);
        }
    }

    /*
     * Creates Certificate instance with the specified certificate.
     */
    public static X509Certificate createCert(String provider, Cert cert) {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance(
                    "X.509", provider);
            return (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(cert.certMaterials.getBytes()));
        } catch (CertificateException | NoSuchProviderException e) {
            throw new RuntimeException("Create cert failed: " + cert, e);
        }
    }

    /*
     * Creates PrivateKey instance with the specified certificate.
     */
    public static PrivateKey createKey(String provider, Cert cert)
            throws NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchProviderException {
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(
                Base64.getMimeDecoder().decode(cert.keyMaterials));

        KeyFactory keyFactory = KeyFactory.getInstance(
                    cert.keyAlgo.name, provider);
        PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);
        return privKey;
    }

    /*
     * Reads an input stream, in which the content length isn't more than 1024.
     */
    public static String readIn(InputStream input) throws IOException {
        byte[] buf = new byte[1024];
        int length = input.read(buf);
        if (length > 0) {
            return new String(buf, 0, length);
        } else {
            return "";
        }
    }

    /*
     * Writes the specified content to an output stream.
     */
    public static void writeOut(OutputStream output, String content)
            throws IOException {
        output.write(content.getBytes(Utilities.CHARSET));
        output.flush();
    }

    /*
     *  Sleeps until the condition is true or getting timeout.
     */
    public static <T> boolean waitFor(Predicate<T> predicate, T t) {
        long deadline = System.currentTimeMillis() + Utilities.TIMEOUT * 1000L;
        boolean predicateResult = predicate.test(t);
        while (!predicateResult && System.currentTimeMillis() < deadline) {
            try {
                TimeUnit.SECONDS.sleep(1);
                predicateResult = predicate.test(t);
            } catch (InterruptedException e) {
                throw new RuntimeException("Sleep is interrupted.", e);
            }
        }

        return predicateResult;
    }

    /*
     * Converts Enum array to string array.
     * The string elements are the Enum names.
     */
    public static String[] enumsToStrs(Enum<?>... elements) {
        return enumsToStrs(Enum::name, elements);
    }

    /*
     * Converts NamedGroup array to string array.
     * The string elements are the NameGroups' names.
     */
    public static String[] namedGroupsToStrs(NamedGroup... namedGroups) {
        return enumsToStrs(Enum::name, namedGroups);
    }

    /*
     * Converts SignatureScheme array to string array.
     * The string elements are the SignatureSchemes' names.
     */
    public static String[] signatureSchemesToStrs(
            SignatureScheme... SignatureSchemes) {
        return enumsToStrs(Enum::name, SignatureSchemes);
    }

    /*
     * Converts Enum array to string array.
     * The string elements are determined by the specified Function.
     */
    public static String[] enumsToStrs(Function<Enum<?>, String> function,
            Enum<?>... elements) {
        return elements == null
                ? null
                : Arrays.stream(elements).map(function).toArray(String[]::new);
    }

    /*
     * Converts string array to Enum array.
     */
    @SuppressWarnings("unchecked")
    public static <T extends Enum<T>> T[] strToEnums(Class<T> enumType,
            String namesStr) {
        if (namesStr == null) {
            return null;
        }

        return Arrays.stream(namesStr.split(VALUE_DELIMITER)).map(name -> {
            return Enum.valueOf(enumType, name);
        }).collect(Collectors.toList()).toArray(
                (T[]) Array.newInstance(enumType, 0));
    }

    /*
     * Determines if the specified process is alive.
     */
    public static boolean isAliveProcess(Process process) {
        return process != null && process.isAlive();
    }

    /*
     * Destroys the specified process and the associated child processes.
     */
    public static void destroyProcess(Process process) {
//        process.children().forEach(ProcessHandle::destroy);
        process.destroy();
    }

    /*
     * Reads the content for the specified file.
     */
    public static Optional<String> readFile(Path path) throws IOException {
        if (!Files.exists(path)) {
            return Optional.empty();
        } else {
            return Optional.of(new String(Files.readAllBytes(path)));
        }
    }

    /*
     * Tries to delete the specified file before getting timeout,
     * in case that the file is not released by some process in time.
     */
    public static void deleteFile(Path filePath) throws IOException {
        if (filePath == null) {
            return;
        }

        waitFor(Utilities::delete, filePath);
        if (Files.exists(filePath)) {
            throw new IOException(
                    "File is not deleted in time: " + filePath.toAbsolutePath());
        }
    }

    private static boolean delete(Path filePath) {
        boolean deleted = false;
        try {
            deleted = Files.deleteIfExists(filePath);
        } catch (IOException e) {
            e.printStackTrace(System.out);
        }

        return deleted;
    }

    /*
     * Determines if the TLS session is resumed.
     */
    public static boolean isSessionResumed(ResumptionMode mode,
            byte[] firstSessionId, byte[] secondSessionId,
            long firstSessionCreationTime, long secondSessionCreationTime) {
        System.out.println("ResumptionMode: " + mode);
        System.out.println("firstSessionId: " + Arrays.toString(firstSessionId));
        System.out.println("secondSessionId: " + Arrays.toString(secondSessionId));
        System.out.println("firstSessionCreationTime: " + firstSessionCreationTime);
        System.out.println("secondSessionCreationTime: " + secondSessionCreationTime);

        boolean resumed = firstSessionCreationTime == secondSessionCreationTime;
        if (mode == ResumptionMode.ID) {
            resumed = resumed && firstSessionId.length > 0
                    && Arrays.equals(firstSessionId, secondSessionId);
        }
        return resumed;
    }

    @SuppressWarnings("unchecked")
    public static <T> String join(String delimiter, Function<T, String> toStr,
            T... elements) {
        if (elements == null) {
            return "";
        }

        StringJoiner joiner = new StringJoiner(delimiter);
        for (T element : elements) {
            if (element != null) {
                String str = toStr.apply(element);
                if (str != null && !str.isEmpty()) {
                    joiner.add(str);
                }
            }
        }
        return joiner.toString();
    }

    @SuppressWarnings("unchecked")
    public static <T> String join(String delimiter, T... elements) {
        return join(delimiter, Object::toString, elements);
    }

    @SuppressWarnings("unchecked")
    public static <T> String join(T... elements) {
        return join(VALUE_DELIMITER, elements);
    }

    @SuppressWarnings("unchecked")
    public static <T> String join(Function<T, String> toStr, T... elements) {
        return join(VALUE_DELIMITER, toStr, elements);
    }

    public static String joinOptValue(String delimiter, String option,
            Object value) {
        return value == null || value.toString().isEmpty()
                ? ""
                : option + delimiter + value;
    }

    public static String joinOptValue(String option, Object value) {
        return joinOptValue(" ", option, value);
    }

    public static String joinNameValue(String option, Object value) {
        return joinOptValue("=", option, value);
    }

    public static String[] split(String str, String delimiter) {
        if (str == null) {
            return null;
        }

        return str.split(delimiter);
    }

    public static String[] split(String str) {
        return split(str, VALUE_DELIMITER);
    }

    public static String trimStr(String str) {
        return str == null ? "" : str.trim();
    }

    public static boolean isEmpty(String str) {
        return str == null || str.isEmpty();
    }

    /*
     * Determines the expected negotiated application protocol from the server
     * and client application protocols.
     */
    public static String expectedNegoAppProtocol(String[] serverAppProtocols,
            String[] clientAppProtocols) {
        if (serverAppProtocols != null && clientAppProtocols != null) {
            for(String clientAppProtocol : clientAppProtocols) {
                for(String serverAppProtocol : serverAppProtocols) {
                    if (clientAppProtocol.equals(serverAppProtocol)) {
                        return clientAppProtocol;
                    }
                }
            }
        }

        return null;
    }

    /*
     * Finds the minimum protocol in the specified protocols.
     */
    public static Protocol minProtocol(Protocol[] protocols) {
        return findProtocol(protocols, true);
    }

    /*
     * Finds the maximum protocol in the specified protocols.
     */
    public static Protocol maxProtocol(Protocol[] protocols) {
        return findProtocol(protocols, false);
    }

    private static Protocol findProtocol(Protocol[] protocols, boolean findMin) {
        if (protocols == null) {
            return null;
        }

        Arrays.sort(protocols, (p1, p2) -> {
            return (p1.id - p2.id) * (findMin ? 1 : -1);
        });
        return protocols[0];
    }
}
