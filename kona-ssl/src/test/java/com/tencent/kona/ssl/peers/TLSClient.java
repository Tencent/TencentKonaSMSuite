package com.tencent.kona.ssl.peers;

import com.tencent.kona.ssl.interop.Cert;
import com.tencent.kona.ssl.interop.CertTuple;
import com.tencent.kona.ssl.interop.CipherSuite;
import com.tencent.kona.ssl.interop.Client;
import com.tencent.kona.ssl.interop.HashAlgorithm;
import com.tencent.kona.ssl.interop.JdkClient;
import com.tencent.kona.ssl.interop.KeyAlgorithm;
import com.tencent.kona.ssl.interop.NamedGroup;
import com.tencent.kona.ssl.interop.Protocol;
import com.tencent.kona.ssl.interop.SignatureAlgorithm;
import com.tencent.kona.ssl.interop.SignatureScheme;
import com.tencent.kona.ssl.TestUtils;

/**
 * A simple client supporting TLS.
 */
public class TLSClient {

    private static final String CA =
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

    private static final String EE =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBozCCAUmgAwIBAgIUJY5VejqP9poKJDhIbaSb67FPLogwCgYIKoEcz1UBg3Uw\n" +
            "EjEQMA4GA1UEAwwHY2EtZGVtbzAeFw0yMTEyMDMwMzM5MTBaFw0zMTEyMDEwMzM5\n" +
            "MTBaMBIxEDAOBgNVBAMMB2VlLWRlbW8wWTATBgcqhkjOPQIBBggqgRzPVQGCLQNC\n" +
            "AASS42fYDx78Zk3T9a0z5Xv1rh/57vfRlvkrlmZsuN7VU1tcHkxUpziRNNJBgHvh\n" +
            "QbQbfMckz9oNQJ5iSCwZL6MRo30wezAdBgNVHQ4EFgQUmAitOYe/FuNu7WwIBIqO\n" +
            "QEWKl/cwHwYDVR0jBBgwFoAUeyMpLtbzSws5xQVV4ujpRzraMkcwOQYDVR0fBDIw\n" +
            "MDAuoCygKoYoZmlsZTpzcmMvdGVzdC9yZXNvdXJjZXMvZGVtby9lZS1kZW1vLmNy\n" +
            "bDAKBggqgRzPVQGDdQNIADBFAiB7ncJGWbHxOhpAyjuKUcLmpvjKlBQoY/rTTo6d\n" +
            "3YERAQIhAKIBruFsEuBKVHz7KBxsd4hsjDrZfWe1n8fzh69pp0zS\n" +
            "-----END CERTIFICATE-----";
    private static final String EE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgKA+GflBSRHU/rjIb\n" +
            "8NSetAkTqaeRwKtkAgkjhoPE63ChRANCAASS42fYDx78Zk3T9a0z5Xv1rh/57vfR\n" +
            "lvkrlmZsuN7VU1tcHkxUpziRNNJBgHvhQbQbfMckz9oNQJ5iSCwZL6MR";

    public static void main(String[] args) throws Exception {
        System.setProperty("com.tencent.misc.useSharedSecrets", "false");
        System.setProperty("com.tencent.kona.ssl.debug", "all");

        TestUtils.addProviders();

        Cert ca = new Cert(
                KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
                CA);
        Cert ee = new Cert(
                KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
                EE, EE_KEY);
        CertTuple certTuple = new CertTuple(ca, ee);

        JdkClient.Builder builder = new JdkClient.Builder();
        builder.setCertTuple(certTuple);
        builder.setProtocols(Protocol.TLSV1_3);
        builder.setCipherSuites(CipherSuite.TLS_SM4_GCM_SM3);
        builder.setNamedGroups(NamedGroup.CURVESM2);
        builder.setSignatureSchemes(SignatureScheme.SM2SIG_SM3);
        builder.setMessage("TLS Client");
        builder.setReadResponse(true);
        try (Client client = builder.build()) {
            client.connect("127.0.0.1", 8443);
        }
    }
}
