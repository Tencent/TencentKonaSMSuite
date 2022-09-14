package com.tencent.kona.pkix.provider;

import com.tencent.kona.crypto.spec.SM2ParameterSpec;
import com.tencent.kona.pkix.PKIXInsts;
import com.tencent.kona.pkix.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

import static com.tencent.kona.pkix.TestUtils.PROVIDER;

/**
 * The test for KeyStore.
 */
public class KeyStoreTest {

    private static final String PASSWD = "password";
    private static final char[] PASSWD_CHARS = PASSWD.toCharArray();
    private static final char[] EMPTY_PASSWD = new char[0];

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testGetKeyStore() throws Exception {
        testGetKeyStore("PKCS12");
        testGetKeyStore("JKS");
    }

    private void testGetKeyStore(String type) throws Exception {
        KeyStore keyStore = PKIXInsts.getKeyStore(type);
        Assertions.assertEquals(
                PROVIDER, keyStore.getProvider().getName());
        Assertions.assertEquals(type, keyStore.getType());
    }

    @Test
    public void testCreateTrustStore() throws Exception {
        testCreateTrustStore("PKCS12");
        testCreateTrustStore("JKS");
    }

    private void testCreateTrustStore(String type) throws Exception {
        KeyStore keyStore = PKIXInsts.getKeyStore(type);
        keyStore.load(null, null);

        keyStore.setCertificateEntry("ca-rsarsa",
                TestUtils.certAsFile("ca-rsarsa.crt"));
        keyStore.setCertificateEntry("ca-p256ecdsa",
                TestUtils.certAsFile("ca-p256ecdsa.crt"));
        keyStore.setCertificateEntry("ca-p256sm2",
                TestUtils.certAsFile("ca-p256sm2.crt"));
        keyStore.setCertificateEntry("ca-sm2ecdsa",
                TestUtils.certAsFile("ca-sm2ecdsa.crt"));
        keyStore.setCertificateEntry("ca-sm2sm2",
                TestUtils.certAsFile("ca-sm2sm2.crt"));

        X509Certificate ca_rsa_rsaCert
                = (X509Certificate) keyStore.getCertificate("ca-rsarsa");
        Assertions.assertEquals("RSA", ca_rsa_rsaCert.getPublicKey().getAlgorithm());
        Assertions.assertEquals("SHA256withRSA", ca_rsa_rsaCert.getSigAlgName());

        X509Certificate ca_p256_ecdsaCert
                = (X509Certificate) keyStore.getCertificate("ca-p256ecdsa");
        Assertions.assertEquals("EC", ca_p256_ecdsaCert.getPublicKey().getAlgorithm());
        Assertions.assertEquals("SHA256withECDSA", ca_p256_ecdsaCert.getSigAlgName());

        X509Certificate ca_p256_sm2Cert
                = (X509Certificate) keyStore.getCertificate("ca-p256sm2");
        Assertions.assertEquals("EC", ca_p256_sm2Cert.getPublicKey().getAlgorithm());
        Assertions.assertEquals("SM3withSM2", ca_p256_sm2Cert.getSigAlgName());

        X509Certificate ca_sm2_p256Cert
                = (X509Certificate) keyStore.getCertificate("ca-sm2ecdsa");
        Assertions.assertEquals("EC", ca_sm2_p256Cert.getPublicKey().getAlgorithm());
        Assertions.assertEquals("SHA256withECDSA", ca_sm2_p256Cert.getSigAlgName());

        X509Certificate ca_sm2_sm2Cert
                = (X509Certificate) keyStore.getCertificate("ca-sm2sm2");
        Assertions.assertEquals("EC", ca_sm2_sm2Cert.getPublicKey().getAlgorithm());
        Assertions.assertEquals("SM3withSM2", ca_sm2_sm2Cert.getSigAlgName());
    }

    @Test
    public void testCreateKeyStore() throws Exception {
        testCreateKeyStore("PKCS12");
        testCreateKeyStore("JKS");
    }

    private void testCreateKeyStore(String type) throws Exception {
        KeyStore keyStore = PKIXInsts.getKeyStore(type);
        keyStore.load(null, null);

        keyStore.setKeyEntry(
                "ee-rsarsa-rsarsa-rsarsa",
                TestUtils.rsaPrivateKeyAsFile("ee-rsarsa-rsarsa-rsarsa.key"),
                EMPTY_PASSWD,
                TestUtils.certChainAsFiles(
                        "ee-rsarsa-rsarsa-rsarsa.crt",
                        "intca-rsarsa-rsarsa.crt",
                        "ca-rsarsa.crt"));
        keyStore.setKeyEntry(
                "ee-p256ecdsa-p256ecdsa-p256ecdsa",
                TestUtils.ecPrivateKeyAsFile("ee-p256ecdsa-p256ecdsa-p256ecdsa.key"),
                EMPTY_PASSWD,
                TestUtils.certChainAsFiles(
                        "ee-p256ecdsa-p256ecdsa-p256ecdsa.crt",
                        "intca-p256ecdsa-p256ecdsa.crt",
                        "ca-p256ecdsa.crt"));
        keyStore.setKeyEntry(
                "ee-p256sm2-sm2ecdsa-p256ecdsa",
                TestUtils.ecPrivateKeyAsFile("ee-p256sm2-sm2ecdsa-p256ecdsa.key"),
                EMPTY_PASSWD,
                TestUtils.certChainAsFiles(
                        "ee-p256sm2-sm2ecdsa-p256ecdsa.crt",
                        "intca-sm2ecdsa-p256ecdsa.crt",
                        "ca-p256ecdsa.crt"));
        keyStore.setKeyEntry(
                "ee-sm2sm2-sm2sm2-sm2sm2",
                TestUtils.ecPrivateKeyAsFile("ee-sm2sm2-sm2sm2-sm2sm2.key"),
                EMPTY_PASSWD,
                TestUtils.certChainAsFiles(
                        "ee-sm2sm2-sm2sm2-sm2sm2.crt",
                        "intca-sm2sm2-sm2sm2.crt",
                        "ca-sm2sm2.crt"));

        keyStore.setKeyEntry(
                "ca-rsarsa_enc",
                TestUtils.encryptedRSAPrivateKeyAsFile(
                        "ca-rsarsa_enc.key", PASSWD),
                PASSWD_CHARS,
                TestUtils.certChainAsFiles("ca-rsarsa.crt"));
        keyStore.setKeyEntry(
                "ca-p256ecdsa_enc",
                TestUtils.encryptedECPrivateKeyAsFile(
                        "ca-p256ecdsa_enc.key", PASSWD),
                PASSWD_CHARS,
                TestUtils.certChainAsFiles("ca-p256ecdsa.crt"));
        keyStore.setKeyEntry(
                "ca-p256sm2_enc",
                TestUtils.encryptedECPrivateKeyAsFile(
                        "ca-p256sm2_enc.key", PASSWD),
                EMPTY_PASSWD,
                TestUtils.certChainAsFiles("ca-p256sm2.crt"));
        keyStore.setKeyEntry(
                "ca-sm2sm2_enc",
                TestUtils.encryptedECPrivateKeyAsFile(
                        "ca-sm2sm2_enc.key", PASSWD),
                PASSWD_CHARS,
                TestUtils.certChainAsFiles("ca-sm2sm2.crt"));

        RSAPrivateKey ee_rsarsa_rsarsa_rsarsaKey
                = (RSAPrivateKey) keyStore.getKey(
                        "ee-rsarsa-rsarsa-rsarsa", EMPTY_PASSWD);
        Assertions.assertEquals("RSA", ee_rsarsa_rsarsa_rsarsaKey.getAlgorithm());
        ECPrivateKey ee_p256ecdsa_p256ecdsa_p256ecdsaKey
                = (ECPrivateKey) keyStore.getKey(
                        "ee-p256ecdsa-p256ecdsa-p256ecdsa", EMPTY_PASSWD);
        Assertions.assertEquals("EC", ee_p256ecdsa_p256ecdsa_p256ecdsaKey.getAlgorithm());
        ECPrivateKey ee_p256sm2_sm2ecdsa_p256ecdsa
                = (ECPrivateKey) keyStore.getKey(
                        "ee-p256sm2-sm2ecdsa-p256ecdsa", EMPTY_PASSWD);
        Assertions.assertEquals("EC", ee_p256sm2_sm2ecdsa_p256ecdsa.getAlgorithm());
        ECPrivateKey ee_sm2sm2_sm2sm2_sm2sm2
                = (ECPrivateKey) keyStore.getKey(
                        "ee-sm2sm2-sm2sm2-sm2sm2", EMPTY_PASSWD);
        Assertions.assertEquals("EC", ee_sm2sm2_sm2sm2_sm2sm2.getAlgorithm());
        Assertions.assertEquals(
                SM2ParameterSpec.instance().getCurve(),
                ee_sm2sm2_sm2sm2_sm2sm2.getParams().getCurve());

        ECPrivateKey ca_p256ecdsa_encKey
                = (ECPrivateKey) keyStore.getKey(
                        "ca-p256ecdsa_enc", PASSWD_CHARS);
        Assertions.assertEquals("EC", ca_p256ecdsa_encKey.getAlgorithm());
        ECPrivateKey ca_p256sm2_encKey
                = (ECPrivateKey) keyStore.getKey(
                        "ca-p256sm2_enc", EMPTY_PASSWD);
        Assertions.assertEquals("EC", ca_p256sm2_encKey.getAlgorithm());
        ECPrivateKey ca_sm2sm2_encKey
                = (ECPrivateKey) keyStore.getKey(
                        "ca-sm2sm2_enc", PASSWD_CHARS);
        Assertions.assertEquals("EC", ca_sm2sm2_encKey.getAlgorithm());
    }

    @Test
    public void testSaveAndLoadKeyStore() throws Exception {
        testSaveAndLoadKeyStore("PKCS12");
        testSaveAndLoadKeyStore("JKS");
    }

    private void testSaveAndLoadKeyStore(String type) throws Exception {
        KeyStore keyStore = PKIXInsts.getKeyStore(type);
        keyStore.load(null, null);

        keyStore.setCertificateEntry("ca-rsarsa",
                TestUtils.certAsFile("ca-rsarsa.crt"));
        keyStore.setCertificateEntry("ca-p256ecdsa",
                TestUtils.certAsFile("ca-p256ecdsa.crt"));
        keyStore.setCertificateEntry("ca-sm2sm2",
                TestUtils.certAsFile("ca-sm2sm2.crt"));

        keyStore.setKeyEntry(
                "ee-rsarsa-rsarsa-rsarsa",
                TestUtils.rsaPrivateKeyAsFile("ee-rsarsa-rsarsa-rsarsa.key"),
                EMPTY_PASSWD,
                TestUtils.certChainAsFiles(
                        "ee-rsarsa-rsarsa-rsarsa.crt",
                        "intca-rsarsa-rsarsa.crt",
                        "ca-rsarsa.crt"));
        keyStore.setKeyEntry(
                "ee-p256ecdsa-p256ecdsa-p256ecdsa",
                TestUtils.ecPrivateKeyAsFile("ee-p256ecdsa-p256ecdsa-p256ecdsa.key"),
                EMPTY_PASSWD,
                TestUtils.certChainAsFiles(
                        "ee-p256ecdsa-p256ecdsa-p256ecdsa.crt",
                        "intca-p256ecdsa-p256ecdsa.crt",
                        "ca-p256ecdsa.crt"));
        keyStore.setKeyEntry(
                "ee-sm2sm2-sm2sm2-sm2sm2",
                TestUtils.ecPrivateKeyAsFile("ee-sm2sm2-sm2sm2-sm2sm2.key"),
                PASSWD_CHARS,
                TestUtils.certChainAsFiles(
                        "ee-sm2sm2-sm2sm2-sm2sm2.crt",
                        "intca-sm2sm2-sm2sm2.crt",
                        "ca-sm2sm2.crt"));

        Path tempKeyStoreFile = Files.createTempDirectory(
                Paths.get("."), "pkix").resolve("test.ks");
        try (FileOutputStream out = new FileOutputStream(
                tempKeyStoreFile.toFile())) {
            keyStore.store(out, PASSWD_CHARS);
        }

        KeyStore loadedKeyStore = PKIXInsts.getKeyStore(type);
        try (FileInputStream keyStoreIn
                = new FileInputStream(tempKeyStoreFile.toFile())) {
            loadedKeyStore.load(keyStoreIn, PASSWD_CHARS);
        } finally {
            Files.deleteIfExists(tempKeyStoreFile);
            Files.deleteIfExists(tempKeyStoreFile.getParent());
        }

        Assertions.assertNotNull(loadedKeyStore.getCertificate("ca-rsarsa"));
        Assertions.assertNotNull(loadedKeyStore.getCertificate("ca-p256ecdsa"));
        Assertions.assertNotNull(loadedKeyStore.getCertificate("ca-sm2sm2"));
        Assertions.assertNotNull(loadedKeyStore.getKey(
                "ee-rsarsa-rsarsa-rsarsa", EMPTY_PASSWD));
        Assertions.assertNotNull(loadedKeyStore.getKey(
                "ee-p256ecdsa-p256ecdsa-p256ecdsa", EMPTY_PASSWD));
        Assertions.assertNotNull(loadedKeyStore.getKey(
                "ee-sm2sm2-sm2sm2-sm2sm2", PASSWD_CHARS));
    }

    @Test
    public void testInterop() throws Exception {
        testInterop("PKCS12", "JDK", PROVIDER);
        testInterop("PKCS12", PROVIDER, "JDK");
        testInterop("JKS", "JDK", PROVIDER);
        testInterop("JKS", PROVIDER, "JDK");
    }

    private void testInterop(String type, String genProvider,
            String loadProvider) throws Exception {
        KeyStore keyStore = null;
        if ("JDK".equals(genProvider)) {
            keyStore = PKIXInsts.getKeyStore(type);
        } else {
            keyStore = KeyStore.getInstance(type, genProvider);
        }
        keyStore.load(null, null);

        keyStore.setCertificateEntry("ca-p256ecdsa",
                TestUtils.certAsFile("ca-p256ecdsa.crt"));
        keyStore.setKeyEntry(
                "ee-p256ecdsa-p256ecdsa-p256ecdsa",
                TestUtils.ecPrivateKeyAsFile("ee-p256ecdsa-p256ecdsa-p256ecdsa.key"),
                PASSWD_CHARS,
                TestUtils.certChainAsFiles(
                        "ee-p256ecdsa-p256ecdsa-p256ecdsa.crt",
                        "intca-p256ecdsa-p256ecdsa.crt",
                        "ca-p256ecdsa.crt"));

        Path tempKeyStoreFile = Files.createTempDirectory(
                Paths.get("."), "pkix").resolve("test-interop.ks");
        try (FileOutputStream out = new FileOutputStream(
                tempKeyStoreFile.toFile())) {
            keyStore.store(out, PASSWD_CHARS);
        }

        KeyStore loadedKeyStore = null;
        if ("JDK".equals(loadProvider)) {
            loadedKeyStore = PKIXInsts.getKeyStore(type);
        } else {
            loadedKeyStore = KeyStore.getInstance(type, loadProvider);
        }
        try (FileInputStream keyStoreIn
                     = new FileInputStream(tempKeyStoreFile.toFile())) {
            loadedKeyStore.load(keyStoreIn, PASSWD_CHARS);
        } finally {
            Files.deleteIfExists(tempKeyStoreFile);
            Files.deleteIfExists(tempKeyStoreFile.getParent());
        }

        Assertions.assertNotNull(loadedKeyStore.getCertificate("ca-p256ecdsa"));
        Assertions.assertNotNull(loadedKeyStore.getKey(
                "ee-p256ecdsa-p256ecdsa-p256ecdsa", PASSWD_CHARS));
    }
}
