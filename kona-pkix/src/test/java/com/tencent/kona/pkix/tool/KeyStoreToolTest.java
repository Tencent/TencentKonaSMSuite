package com.tencent.kona.pkix.tool;

import com.tencent.kona.pkix.PKIXInsts;
import com.tencent.kona.pkix.TestUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;

public class KeyStoreToolTest {

    private static final String TRUST_STORE_P12 = "truststore.p12";
    private static final String TRUST_STORE_JKS = "truststore.jks";
    private static final String KEY_STORE_P12 = "keystore.p12";
    private static final String KEY_STORE_JKS = "keystore.jks";
    private static final String STORE_P12 = "store.p12";
    private static final String STORE_JKS = "store.jks";

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
        Assertions.assertEquals("keyPassword", keyEntryArguments.keyPasswd);
        Assertions.assertEquals("/path/to/certchain.pem", keyEntryArguments.certs);
        Assertions.assertEquals("/path/to/keystore.p12", keyEntryArguments.store);
        Assertions.assertEquals("KeystorePassword", keyEntryArguments.storePasswd);
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
        Assertions.assertEquals("TruststorePassword", trustEntryArgs.storePasswd);
    }

    @Test
    public void testCreatePKCS12TrustStore() throws Exception {
        testCreateTrustStore("PKCS12", TRUST_STORE_P12, "truststorepass");
    }

    @Test
    public void testCreateJKSTrustStore() throws Exception {
        testCreateTrustStore("JKS", TRUST_STORE_JKS, "truststorepass");
    }

    private void testCreateTrustStore(String type, String storeFilePath,
            String storePasswd) throws Exception {
        String tlcpCAAlias = "tlcp-ca";
        String rsaCAAlias = "rsa-ca";
        String trustCertsPath = TestUtils.resFilePath("tool/trust_certs.pem").toString();
        Path storePath = Paths.get(storeFilePath).toAbsolutePath();

        String[] args = new String[] {
                "-type", type,
                "-alias", tlcpCAAlias + "," + rsaCAAlias,
                "-certs", trustCertsPath,
                "-store", storePath.toString(),
                "-storePasswd", storePasswd };
        KeyStoreTool.main(args);
        Assertions.assertTrue(Files.exists(storePath));

        KeyStore trustStore = PKIXInsts.getKeyStore(type);
        trustStore.load(new FileInputStream(storePath.toString()),
                storePasswd.toCharArray());
        Assertions.assertNotNull(trustStore.getCertificate(tlcpCAAlias));
        Assertions.assertNotNull(trustStore.getCertificate(rsaCAAlias));
        Assertions.assertNull(trustStore.getCertificate("x"));
    }

    @Test
    public void testCreatePKCS12KeyStore() throws Exception {
        testCreateKeyStore("PKCS12", KEY_STORE_P12, "keystorepass");
    }

    @Test
    public void testCreateJKSKeyStore() throws Exception {
        testCreateKeyStore("JKS", KEY_STORE_JKS, "keystorepass");
    }

    private void testCreateKeyStore(String type, String storeFilePath,
            String storePasswd) throws Exception {
        String signAlias = "sign";
        String signKeyPath = TestUtils.resFilePath("tool/sign_key.pem").toString();
        String signCertChainPath = TestUtils.resFilePath("tool/sign_cert_chain.pem").toString();

        String encAlias = "enc";
        String encKeyPath = TestUtils.resFilePath("tool/enc_key.pem").toString();
        String encCertChainPath = TestUtils.resFilePath("tool/enc_cert_chain.pem").toString();

        Path storePath = Paths.get(storeFilePath).toAbsolutePath();

        String[] signArgs = new String[] {
                "-type", type,
                "-alias", signAlias,
                "-keyAlgo", "EC",
                "-key", signKeyPath,
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
                "-key", encKeyPath,
                "-keyPasswd", "enckeypass",
                "-certs", encCertChainPath,
                "-store", storePath.toString(),
                "-storePasswd", storePasswd };
        KeyStoreTool.main(encArgs);

        KeyStore trustStore = PKIXInsts.getKeyStore(type);
        trustStore.load(new FileInputStream(storePath.toString()),
                storePasswd.toCharArray());
        Assertions.assertNotNull(trustStore.getCertificate(signAlias));
        Assertions.assertNotNull(trustStore.getCertificate(encAlias));
    }

    @Test
    public void testCreatePKCS12TrustAndKeyStore() throws Exception {
        testCreateTrustAndKeyStore("PKCS12", STORE_P12);
    }

    @Test
    public void testCreateJKSTrustAndKeyStore() throws Exception {
        testCreateTrustAndKeyStore("JKS", STORE_JKS);
    }

    private void testCreateTrustAndKeyStore(String type, String storeFile)
            throws Exception {
        String storePasswd = "storepass";
        testCreateTrustStore(type, storeFile, storePasswd);
        testCreateKeyStore(type, storeFile, storePasswd);
    }

    @AfterAll
    public static void clean() throws IOException {
        Files.deleteIfExists(Paths.get(TRUST_STORE_P12));
        Files.deleteIfExists(Paths.get(TRUST_STORE_JKS));
        Files.deleteIfExists(Paths.get(KEY_STORE_P12));
        Files.deleteIfExists(Paths.get(KEY_STORE_JKS));
        Files.deleteIfExists(Paths.get(STORE_P12));
        Files.deleteIfExists(Paths.get(STORE_JKS));
    }
}
