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

import com.tencent.kona.ssl.interop.*;
import com.tencent.kona.ssl.TestUtils;

import javax.net.ssl.SSLContext;

/**
 * A simple server supporting TLCP.
 */
public class TLCPClient {

    private static final String CA =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBjDCCATKgAwIBAgIUc1kBltJcsvucxFYD+CzKcGvuNHowCgYIKoEcz1UBg3Uw\n" +
            "EjEQMA4GA1UEAwwHdGxjcC1jYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgxMTU2\n" +
            "MzhaMBUxEzARBgNVBAMMCnRsY3AtaW50Y2EwWTATBgcqhkjOPQIBBggqgRzPVQGC\n" +
            "LQNCAAS1g0eBwqPefYRBc2zyZlJi6jyfF7RlsFspKwF5LMxkcYMblZXjlUYVhnpN\n" +
            "F3N/x2knleNfrXrdTTR3Yv2MIMGQo2MwYTAdBgNVHQ4EFgQURS/dNZJ+d0Sel9TW\n" +
            "vGNYGWnxTb4wHwYDVR0jBBgwFoAUQI8lwKZzxP/OpobF4UNyPG3JiocwDwYDVR0T\n" +
            "AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwCgYIKoEcz1UBg3UDSAAwRQIhAI79\n" +
            "0T0rhbYCdqdGqbYxidgyr1XRpXncwRqmx7a+IDkvAiBDPtfFfB/UiwO4wBLqxwJO\n" +
            "+xEdTF+d/Wfro9fxSnrqEw==\n" +
            "-----END CERTIFICATE-----";

    private static final String SIGN_EE =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBkzCCATigAwIBAgIUGPbVJN01IrLr9fslSIdO4rqpcwQwCgYIKoEcz1UBg3Uw\n" +
            "FTETMBEGA1UEAwwKdGxjcC1pbnRjYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgx\n" +
            "MTU2MzhaMBsxGTAXBgNVBAMMEHRsY3AtY2xpZW50LXNpZ24wWTATBgcqhkjOPQIB\n" +
            "BggqgRzPVQGCLQNCAASPBt+HBVc3bmQkKHNR6EQVdSS905HiiOphVGuDwHrMpzUm\n" +
            "Qh3C4zNqdSlp0PUS8NK3imLBpMxng+FMnM6bDefXo2AwXjAdBgNVHQ4EFgQUM7U5\n" +
            "/ErJ5ZdOZVUGvFqUAQyW70AwHwYDVR0jBBgwFoAURS/dNZJ+d0Sel9TWvGNYGWnx\n" +
            "Tb4wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwCgYIKoEcz1UBg3UDSQAw\n" +
            "RgIhANKxFf6vSIWsACuxWGCG4/uJmc82jAIKCCrWH09KIt5kAiEA0XGSRL+mZu2L\n" +
            "1jf5zKhE6ASDdV634fDEknKcsLkuvvU=\n" +
            "-----END CERTIFICATE-----";
    private static final String SIGN_EE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgulutgxQDiBzTCYiu\n" +
            "adobFrKgK/umEjLmUKTUjUKXVI+hRANCAASPBt+HBVc3bmQkKHNR6EQVdSS905Hi\n" +
            "iOphVGuDwHrMpzUmQh3C4zNqdSlp0PUS8NK3imLBpMxng+FMnM6bDefX";

    private static final String ENC_EE =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBkTCCATegAwIBAgIUGPbVJN01IrLr9fslSIdO4rqpcwcwCgYIKoEcz1UBg3Uw\n" +
            "FTETMBEGA1UEAwwKdGxjcC1pbnRjYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgx\n" +
            "MTU2MzhaMBoxGDAWBgNVBAMMD3RsY3AtY2xpZW50LWVuYzBZMBMGByqGSM49AgEG\n" +
            "CCqBHM9VAYItA0IABF8BHUkVbNgU/EmoZlSAWbPcMHuV2LZU62AJElRf/ZasTmMH\n" +
            "uhdtOAnoIkvuBh+yJZBjKM/0avFAbCDY5Mjo8RKjYDBeMB0GA1UdDgQWBBSjHJvH\n" +
            "aqrfqkgfyR7af6BSlPyXHTAfBgNVHSMEGDAWgBRFL901kn53RJ6X1Na8Y1gZafFN\n" +
            "vjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIDODAKBggqgRzPVQGDdQNIADBF\n" +
            "AiEAwBlUP46RdSR2eBgMe30DcMXDUcdv/W1stRGWS0znQB0CIG2pC+yOAe+R97JW\n" +
            "Nvbb8xtPrMYkjrU5emCH2H0a6eHz\n" +
            "-----END CERTIFICATE-----";
    private static final String ENC_EE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgqrW1N+3YxmSDz7KX\n" +
            "dCH238n62DR6/3Fw4723EaMFh2GhRANCAARfAR1JFWzYFPxJqGZUgFmz3DB7ldi2\n" +
            "VOtgCRJUX/2WrE5jB7oXbTgJ6CJL7gYfsiWQYyjP9GrxQGwg2OTI6PES";

    public static void main(String[] args) throws Exception {
        System.setProperty("com.tencent.misc.useSharedSecrets", "false");
        System.setProperty("com.tencent.kona.ssl.debug", "all");

        String host = "localhost";
        int port = 8444;

        TestUtils.addProviders();

        Cert ca = new Cert(
                KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
                CA);
        Cert signEE = new Cert(
                KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
                SIGN_EE, SIGN_EE_KEY);
        Cert encEE = new Cert(
                KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
                ENC_EE, ENC_EE_KEY);
        SmCertTuple certTuple = new SmCertTuple(ca, signEE, encEE);

        SSLContext context = null;

        try (JdkClient client = createClient(
                certTuple, Protocol.TLCPV1_1, CipherSuite.TLCP_ECC_SM4_GCM_SM3,
                context)) {
            client.connect(host, port);
            context = client.context;
        }

        try (JdkClient client = createClient(
                certTuple, Protocol.TLCPV1_1, CipherSuite.TLCP_ECC_SM4_GCM_SM3,
                context)) {
            client.connect(host, port);
        }
    }

    private static JdkClient createClient(
            CertTuple certTuple, Protocol protocol, CipherSuite cipherSuite,
            SSLContext context) throws Exception {
        JdkClient.Builder builder = new JdkClient.Builder();
        builder.setContextProtocol(ContextProtocol.TLCP);
        builder.setCertTuple(certTuple);
        builder.setProtocols(protocol);
        builder.setCipherSuites(cipherSuite);
        builder.setMessage("Client");
        builder.setReadResponse(true);
        builder.setContext(context);
        return builder.build();
    }
}
