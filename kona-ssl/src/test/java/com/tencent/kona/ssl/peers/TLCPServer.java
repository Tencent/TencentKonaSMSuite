/*
 * Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
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
import com.tencent.kona.ssl.interop.ClientAuth;
import com.tencent.kona.ssl.interop.ContextProtocol;
import com.tencent.kona.ssl.interop.HashAlgorithm;
import com.tencent.kona.ssl.interop.JdkServer;
import com.tencent.kona.ssl.interop.KeyAlgorithm;
import com.tencent.kona.ssl.interop.Server;
import com.tencent.kona.ssl.interop.SignatureAlgorithm;
import com.tencent.kona.ssl.interop.SmCertTuple;
import com.tencent.kona.ssl.TestUtils;

/**
 * A simple server supporting TLCP.
 */
public class TLCPServer {

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
            "MIIBkjCCATigAwIBAgIUGPbVJN01IrLr9fslSIdO4rqpcwMwCgYIKoEcz1UBg3Uw\n" +
            "FTETMBEGA1UEAwwKdGxjcC1pbnRjYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgx\n" +
            "MTU2MzhaMBsxGTAXBgNVBAMMEHRsY3Atc2VydmVyLXNpZ24wWTATBgcqhkjOPQIB\n" +
            "BggqgRzPVQGCLQNCAARYT1t4ecS5pLkQlA9smyxe1tictMdl/x4AbO8nI07CHjXK\n" +
            "HPhtPzJLvKFH2qqQTZmn4LnfLqaPgGjx8ymqRuODo2AwXjAdBgNVHQ4EFgQUIerW\n" +
            "JjprHQfhD6ETgBX0G8dWWGswHwYDVR0jBBgwFoAURS/dNZJ+d0Sel9TWvGNYGWnx\n" +
            "Tb4wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwCgYIKoEcz1UBg3UDSAAw\n" +
            "RQIgW88b4/7Rgj0QVkHR49zINniwxdjotBRkSwdKNkVtt7YCIQCkjttpnM3HU0v7\n" +
            "NYFodEcndjXj9RDGujYO9NxgegXpSg==\n" +
            "-----END CERTIFICATE-----";
    private static final String SIGN_EE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg6wAH+egoZkKS3LKi\n" +
            "0okzJSYrn/yRVhNfmdhySuJic5ahRANCAARYT1t4ecS5pLkQlA9smyxe1tictMdl\n" +
            "/x4AbO8nI07CHjXKHPhtPzJLvKFH2qqQTZmn4LnfLqaPgGjx8ymqRuOD";

    private static final String ENC_EE =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBkDCCATegAwIBAgIUGPbVJN01IrLr9fslSIdO4rqpcwYwCgYIKoEcz1UBg3Uw\n" +
            "FTETMBEGA1UEAwwKdGxjcC1pbnRjYTAeFw0yMjA1MTExMTU2MzhaFw0zMjA1MDgx\n" +
            "MTU2MzhaMBoxGDAWBgNVBAMMD3RsY3Atc2VydmVyLWVuYzBZMBMGByqGSM49AgEG\n" +
            "CCqBHM9VAYItA0IABAQbatb13gJL3zt1B8U5LoheRJ+4XnRpqIQ5Osx0VDk4UW25\n" +
            "8aLlU96bf3onvnHThpa9GwHbY5BpYsMP1hS+1kCjYDBeMB0GA1UdDgQWBBQ0KNMH\n" +
            "KtXGecDXiEtTjCfhpDh5CDAfBgNVHSMEGDAWgBRFL901kn53RJ6X1Na8Y1gZafFN\n" +
            "vjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIDODAKBggqgRzPVQGDdQNHADBE\n" +
            "AiAD2eC+F7kTZGbH2lHG7ZTOzx62OYo1MSn31+hKHfbZ9AIgazWIQMJ0MQfn/qX5\n" +
            "z0Ez8iVqyDxZyHIOFjbr1DZEQEk=\n" +
            "-----END CERTIFICATE-----";
    private static final String ENC_EE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgqFilR+zUyRQWREb+\n" +
            "rb5uIldK/bPE1l20DzNpuMt55VehRANCAAQEG2rW9d4CS987dQfFOS6IXkSfuF50\n" +
            "aaiEOTrMdFQ5OFFtufGi5VPem396J75x04aWvRsB22OQaWLDD9YUvtZA";

    public static void main(String[] args) throws Exception {
        System.setProperty("com.tencent.misc.useSharedSecrets", "false");
        System.setProperty("com.tencent.kona.ssl.debug", "all");

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

        JdkServer.Builder builder = new JdkServer.Builder();
        builder.setContextProtocol(ContextProtocol.TLCP);
        builder.setCertTuple(certTuple);
        builder.setClientAuth(ClientAuth.REQUIRED);
        builder.setMessage("TLCP Server");
        builder.setTimeout(10 * 60 * 1000);
        builder.setPort(8444);

        Server server = builder.build();
        System.out.println("port: " + server.getPort());
        server.accept();
    }
}
