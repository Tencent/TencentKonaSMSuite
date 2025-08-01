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

package com.tencent.kona.ssl.peers;

import com.tencent.kona.ssl.interop.Cert;
import com.tencent.kona.ssl.interop.CertTuple;
import com.tencent.kona.ssl.interop.CipherSuite;
import com.tencent.kona.ssl.interop.HashAlgorithm;
import com.tencent.kona.ssl.interop.JdkClient;
import com.tencent.kona.ssl.interop.KeyAlgorithm;
import com.tencent.kona.ssl.interop.NamedGroup;
import com.tencent.kona.ssl.interop.Protocol;
import com.tencent.kona.ssl.interop.SignatureAlgorithm;
import com.tencent.kona.ssl.interop.SignatureScheme;
import com.tencent.kona.ssl.TestUtils;

import javax.net.ssl.SSLContext;

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

        String host = "localhost";
        int port = 8443;

        TestUtils.addProviders();

        Cert ca = new Cert(
                KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
                CA);
        Cert ee = new Cert(
                KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
                EE, EE_KEY);
        CertTuple certTuple = new CertTuple(ca, ee);

        SSLContext context = null;

        try (JdkClient client = createClient(
                certTuple, Protocol.TLSV1_3, CipherSuite.TLS_SM4_GCM_SM3,
                new NamedGroup[]{NamedGroup.CURVESM2},
                new SignatureScheme[] {SignatureScheme.SM2SIG_SM3},
                context)) {
            client.connect(host, port);
            context = client.context;
        }

        try (JdkClient client = createClient(
                certTuple, Protocol.TLSV1_3, CipherSuite.TLS_SM4_GCM_SM3,
                new NamedGroup[]{NamedGroup.CURVESM2},
                new SignatureScheme[] {SignatureScheme.SM2SIG_SM3},
                context)) {
            client.connect(host, port);
        }
    }

    private static JdkClient createClient(
            CertTuple certTuple, Protocol protocol, CipherSuite cipherSuite,
            NamedGroup[] namedGroups, SignatureScheme[] signatureSchemes,
            SSLContext context) throws Exception {
        JdkClient.Builder builder = new JdkClient.Builder();
        builder.setCertTuple(certTuple);
        builder.setProtocols(protocol);
        builder.setCipherSuites(cipherSuite);
        builder.setNamedGroups(namedGroups);
        builder.setSignatureSchemes(signatureSchemes);
        builder.setMessage("Client");
        builder.setReadResponse(true);
        builder.setContext(context);
        return builder.build();
    }
}
