package com.tencent.kona.pkix;

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.crypto.CryptoUtils;
import com.tencent.kona.crypto.KonaCryptoProvider;
import com.tencent.kona.javax.crypto.EncryptedPrivateKeyInfo;
import com.tencent.kona.pkix.process.OutputAnalyzer;
import com.tencent.kona.pkix.process.ProcessTools;

import javax.crypto.Cipher;
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
import java.security.AlgorithmParameters;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
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

    private static final String JAVA_HOME = System.getProperty("java.home");
    private static final String JAVA
            = String.join(File.separator, JAVA_HOME, "bin", "java");

    public static final String PROVIDER = PKIXInsts.PROV_NAME;

    private static final String BEGIN = "-----BEGIN";
    private static final String END = "-----END";

    private static final Path TEST_RES_PATH
            = Paths.get("src/test/resources");

    private static final String CLASSPATH = System.getProperty("test.classpath");
    private static final List<String> JDK11_OPTIONS = Arrays.asList(
            "--add-exports", "java.base/jdk.internal.misc=ALL-UNNAMED");
    private static final List<String> JDK17_OPTIONS = Arrays.asList(
            "--add-exports", "java.base/jdk.internal.access=ALL-UNNAMED");

    public static void addProviders() {
        Security.addProvider(new KonaCryptoProvider());
        Security.addProvider(new KonaPKIXProvider());
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
        return (RSAPrivateKey) privateKey("RSA", keyStr(keyFileName));
    }

    public static ECPrivateKey ecPrivateKeyAsFile(String keyFileName)
            throws Exception {
        return (ECPrivateKey) privateKey("EC", keyStr(keyFileName));
    }

    public static ECPrivateKey ecPrivateKey(String keyPEM)
            throws Exception {
        return (ECPrivateKey) privateKey("EC", keyPEM);
    }

    private static PrivateKey privateKey(
            String keyAlgo, String keyPEM) throws Exception {
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                Base64.getMimeDecoder().decode(keyPEM));
        KeyFactory keyFactory = CryptoInsts.getKeyFactory(keyAlgo);
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

    private static PrivateKey encryptedPrivateKey(
            String keyAlg, String encryptedKeyPEM, String passphrase)
            throws Exception {
        EncryptedPrivateKeyInfo encryptedPrivateKeyInfo
                = new EncryptedPrivateKeyInfo(
                        Base64.getMimeDecoder().decode(encryptedKeyPEM));
        String pbeAlg = encryptedPrivateKeyInfo.getAlgName();
        AlgorithmParameters params = encryptedPrivateKeyInfo.getAlgParameters();

        SecretKeyFactory pbeKeyFactory = SecretKeyFactory.getInstance(pbeAlg);
        Key pbeKey = pbeKeyFactory.generateSecret(new PBEKeySpec(
                passphrase.toCharArray()));
        Cipher cipher = CryptoInsts.getCipher(pbeAlg);
        cipher.init(Cipher.DECRYPT_MODE, pbeKey, params);
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
        KeyStore keyStore = PKIXInsts.getKeyStore("PKCS12");
        keyStore.load(null, null);

        for (int i = 0; i < aliases.length; i++) {
            keyStore.setCertificateEntry(aliases[i], cert(certStrs[i]));
        }

        return keyStore;
    }

    public static KeyStore keyStore(String alias, String keyStr,
            char[] password, String[] certStrs) throws Exception {
        KeyStore keyStore = PKIXInsts.getKeyStore("PKCS12");;
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

    public static void checkThrowable(Class<? extends Throwable> throwableClass,
                                      Executable executable,
                                      boolean requiredExpectedException) {
        try {
            executable.execute();
            if (requiredExpectedException) {
                throw new AssertionError("Expected exception did not raise");
            } else {
                System.out.println("Expected exception did not raise, " +
                        "though that's not a matter");
            }
        } catch(Throwable e) {
            if (!throwableClass.isInstance(e)) {
                throw new AssertionError("Unexpected exception: ", e);
            }
        }
    }

    public static void checkThrowable(Class<? extends Throwable> throwableClass,
                                      Executable executable) {
        checkThrowable(throwableClass, executable, true);
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

    public static OutputAnalyzer java(Class<?> clazz, List<String> args)
            throws Throwable {
        return java(null, clazz, args);
    }

    public static OutputAnalyzer java(List<String> jvmOptions, Class<?> clazz,
            List<String> args) throws Throwable {
        List<String> allJVMOptions = new ArrayList<>();

        if (jvmOptions != null) {
            allJVMOptions.addAll(jvmOptions);
        }

        if (CryptoUtils.isJdk11()) {
            allJVMOptions.addAll(JDK11_OPTIONS);
        } else if (CryptoUtils.isJdk17()) {
            allJVMOptions.addAll(JDK17_OPTIONS);
        }

        return createProcessBuilder(
                Paths.get(JAVA), allJVMOptions, CLASSPATH, clazz, args);
    }

    private static OutputAnalyzer createProcessBuilder(Path javaPath,
            List<String> jvmOptions, String classpath, Class<?> clazz,
            List<String> arguments) throws Throwable {
        List<String> cmds = new ArrayList<>();
        cmds.add(javaPath.toString());

        if (jvmOptions != null) {
            cmds.addAll(jvmOptions);
        }

        cmds.add("-cp");
        cmds.add(classpath);

        cmds.add(clazz.getName());
        if (arguments != null) {
            cmds.addAll(arguments);
        }

        return ProcessTools.executeProcess(cmds.toArray(new String[0]));
    }

    public static void deleteDirIfExists(Path dir) throws IOException {
        if (!Files.exists(dir)) {
            return;
        }

        Files.walk(dir)
                .sorted(Comparator.reverseOrder())
                .map(Path::toFile)
                .forEach(File::delete);
    }
}
