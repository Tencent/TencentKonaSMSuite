package com.tencent.kona.ssl;

import com.tencent.kona.pkix.PKIXUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;

/**
 * The test for Utils.
 */
public class SSLUtilsTest {

    /* The CA certificate.
     *
     * Certificate:
     *     Data:
     *         Version: 3 (0x2)
     *         Serial Number:
     *             74:7a:13:d4:70:5d:74:07:fd:33:58:4d:8e:6b:da:7d:25:8c:73:a3
     *         Signature Algorithm: sm3WithSM2Sign
     *         Issuer: CN = ca-demo
     *         Validity
     *             Not Before: Dec  1 03:24:15 2021 GMT
     *             Not After : Nov 29 03:24:15 2031 GMT
     *         Subject: CN = ca-demo
     *         Subject Public Key Info:
     *             Public Key Algorithm: id-ecPublicKey
     *                 Public-Key: (256 bit)
     *                 pub:
     *                     04:cd:ba:07:1b:e9:60:50:36:66:44:ed:54:be:32:
     *                     0e:78:cd:4d:3b:83:79:be:18:b0:2d:8e:c7:1c:0f:
     *                     47:90:ed:2c:17:a6:33:f8:9c:da:24:6b:1e:98:23:
     *                     32:b9:94:9e:a6:ac:ce:98:d8:65:79:02:f8:da:22:
     *                     65:9b:ba:27:56
     *                 ASN1 OID: SM2
     *         X509v3 extensions:
     *             X509v3 Subject Key Identifier:
     *                 7B:23:29:2E:D6:F3:4B:0B:39:C5:05:55:E2:E8:E9:47:3A:DA:32:47
     *             X509v3 Authority Key Identifier:
     *                 keyid:7B:23:29:2E:D6:F3:4B:0B:39:C5:05:55:E2:E8:E9:47:3A:DA:32:47
     *
     *             X509v3 Basic Constraints: critical
     *                 CA:TRUE
     *             X509v3 Key Usage: critical
     *                 Digital Signature, Certificate Sign, CRL Sign
     *             X509v3 Extended Key Usage: critical
     *                 OCSP Signing
     *     Signature Algorithm: sm3WithSM2Sign
     *          30:46:02:21:00:ed:49:c1:18:b8:a1:55:30:60:58:58:31:d2:
     *          92:46:65:a3:5d:c1:65:d2:80:23:10:e3:03:ff:ce:ef:84:d7:
     *          93:02:21:00:ba:62:2f:5d:bb:cd:6e:9d:2b:8c:39:97:bd:82:
     *          b8:07:5a:11:2a:12:c2:cf:55:50:02:a3:9c:0a:17:9c:8a:51
     */
    private static final String CERT =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBojCCAUegAwIBAgIUdHoT1HBddAf9M1hNjmvafSWMc6MwCgYIKoEcz1UBg3Uw\n" +
            "EjEQMA4GA1UEAwwHY2EtZGVtbzAeFw0yMTEyMDEwMzI0MTVaFw0zMTExMjkwMzI0\n" +
            "MTVaMBIxEDAOBgNVBAMMB2NhLWRlbW8wWTATBgcqhkjOPQIBBggqgRzPVQGCLQNC\n" +
            "AATNugcb6WBQNmZE7VS+Mg54zU07g3m+GLAtjsccD0eQ7SwXpjP4nNokax6YIzK5\n" +
            "lJ6mrM6Y2GV5AvjaImWbuidWo3sweTAdBgNVHQ4EFgQUeyMpLtbzSws5xQVV4ujp\n" +
            "RzraMkcwHwYDVR0jBBgwFoAUeyMpLtbzSws5xQVV4ujpRzraMkcwDwYDVR0TAQH/\n" +
            "BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwkw\n" +
            "CgYIKoEcz1UBg3UDSQAwRgIhAO1JwRi4oVUwYFhYMdKSRmWjXcFl0oAjEOMD/87v\n" +
            "hNeTAiEAumIvXbvNbp0rjDmXvYK4B1oRKhLCz1VQAqOcChecilE=\n" +
            "-----END CERTIFICATE-----";

    private static final String KEY =
            "-----BEGIN PRIVATE KEY-----\n" +
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgqiXZE9IGb/jccQdf\n" +
            "2WYJNk+KVWk8/pPwWx5giD06FX+hRANCAATNugcb6WBQNmZE7VS+Mg54zU07g3m+\n" +
            "GLAtjsccD0eQ7SwXpjP4nNokax6YIzK5lJ6mrM6Y2GV5AvjaImWbuidW" +
            "-----END PRIVATE KEY-----";

    private static final String KEY_WITHOUT_BE =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgqiXZE9IGb/jccQdf\n" +
            "2WYJNk+KVWk8/pPwWx5giD06FX+hRANCAATNugcb6WBQNmZE7VS+Mg54zU07g3m+\n" +
            "GLAtjsccD0eQ7SwXpjP4nNokax6YIzK5lJ6mrM6Y2GV5AvjaImWbuidW";

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testGetPrivateKey() throws Exception {
        testGetPrivateKey(KEY);
    }

    @Test
    public void testGetPrivateKeyWithoutBELines() throws Exception {
        testGetPrivateKey(KEY_WITHOUT_BE);
    }

    private void testGetPrivateKey(String keyStr) throws Exception {
        ECPrivateKey key = (ECPrivateKey) PKIXUtils.getPrivateKey("EC", keyStr);
        Assertions.assertEquals(key.getAlgorithm(), "EC");
    }

    @Test
    public void testGetPublicKey() throws Exception {
        PublicKey key = PKIXUtils.getPublicKey(CERT);
        Assertions.assertEquals(key.getAlgorithm(), "EC");
    }

    @Test
    public void testGetCertificate() throws Exception {
        X509Certificate cert = PKIXUtils.getCertificate(CERT);
        Assertions.assertEquals(cert.getSigAlgName(), "SM3withSM2");
    }
}
