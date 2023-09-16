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
import com.tencent.kona.ssl.interop.CertTuple;
import com.tencent.kona.ssl.interop.CipherSuite;
import com.tencent.kona.ssl.interop.ClientAuth;
import com.tencent.kona.ssl.interop.ContextProtocol;
import com.tencent.kona.ssl.interop.HashAlgorithm;
import com.tencent.kona.ssl.interop.JdkServer;
import com.tencent.kona.ssl.interop.KeyAlgorithm;
import com.tencent.kona.ssl.interop.Protocol;
import com.tencent.kona.ssl.interop.Provider;
import com.tencent.kona.ssl.interop.Server;
import com.tencent.kona.ssl.interop.SignatureAlgorithm;

/**
 * A simple server supporting TLS with JSSE provider.
 */
public class SunJSSEServer {

    private static final String CA =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBuTCCAV6gAwIBAgIUKmWv3/Tfg1gkaPNURtNO0/SkjwkwCgYIKoZIzj0EAwIw\n" +
            "FzEVMBMGA1UEAwwMY2EtcDI1NmVjZHNhMB4XDTIxMDkxMTIwMTUxNloXDTMxMDkw\n" +
            "OTIwMTUxNlowJDEiMCAGA1UEAwwZaW50Y2EtcDI1NmVjZHNhLXAyNTZlY2RzYTBZ\n" +
            "MBMGByqGSM49AgEGCCqGSM49AwEHA0IABI8zS78F3eCOnknb9CUI6taz7YXgAEPp\n" +
            "V03N11zF10EN1jaf7Zw33OFSKCEPaCFvvmV5RV57Q9+kgoS3NqR8kiajezB5MB0G\n" +
            "A1UdDgQWBBRwFJlygX8L0akeiDbS5kiXj4e4VTAfBgNVHSMEGDAWgBSuBXJlqm8G\n" +
            "BJPn1y8OACYcWIhDzzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAW\n" +
            "BgNVHSUBAf8EDDAKBggrBgEFBQcDCTAKBggqhkjOPQQDAgNJADBGAiEAt6X+tCHd\n" +
            "oFAJ4qSwCGZ3Y9QiHtKy4bKRhMdFpZxAIWICIQCe4lH45iSB93JDQ6uQbjjfdjSh\n" +
            "uWUvOaC8egBzIpFaFQ==\n" +
            "-----END CERTIFICATE-----";

    private static final String EE =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIBkzCCATmgAwIBAgIUfMbvyf8bQEpMEYXnFNuCbGFXMSUwCgYIKoZIzj0EAwIw\n" +
            "JDEiMCAGA1UEAwwZaW50Y2EtcDI1NmVjZHNhLXAyNTZlY2RzYTAeFw0yMTA5MTEy\n" +
            "MDE1MTZaFw0zMTA5MDkyMDE1MTZaMCsxKTAnBgNVBAMMIGVlLXAyNTZlY2RzYS1w\n" +
            "MjU2ZWNkc2EtcDI1NmVjZHNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtfjR\n" +
            "0wNCRllUUk1sGpGsriOEJBCtWKjCgDr4FA8F4KmYGVEOKeJ90eJcbgNa0T1eyJFE\n" +
            "CGw/DkpXONbejD9Bc6NCMEAwHQYDVR0OBBYEFPLWXqOSjnjRwO7LqoLSaGg+oMhg\n" +
            "MB8GA1UdIwQYMBaAFHAUmXKBfwvRqR6INtLmSJePh7hVMAoGCCqGSM49BAMCA0gA\n" +
            "MEUCIQCDDTDSpHSdfdC2SkUwXDvuglW5dmGPrFVk6JcNdCUIcgIgYwbGn7MVijT7\n" +
            "g5qUdXF/YsUEFsTZage7fAltZ7AcARU=\n" +
            "-----END CERTIFICATE-----";
    private static final String EE_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZY/ebcIPzj+r0Jf7\n" +
            "xiH0qu5fsCLlkGTlgnMBuaDQqOahRANCAAS1+NHTA0JGWVRSTWwakayuI4QkEK1Y\n" +
            "qMKAOvgUDwXgqZgZUQ4p4n3R4lxuA1rRPV7IkUQIbD8OSlc41t6MP0Fz";

    public static void main(String[] args) throws Exception {
        System.setProperty("javax.net.debug", "all");

        Cert ca = new Cert(
                KeyAlgorithm.EC, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256,
                CA);
        Cert ee = new Cert(
                KeyAlgorithm.EC, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256,
                EE, EE_KEY);
        CertTuple certTuple = new CertTuple(ca, ee);

        JdkServer.Builder builder = new JdkServer.Builder();
        builder.setProvider(Provider.JDK);
        builder.setContextProtocol(ContextProtocol.TLS);
        builder.setCertTuple(certTuple);
        builder.setProtocols(Protocol.TLSV1_3, Protocol.TLSV1_2);
        builder.setCipherSuites(
                CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        builder.setClientAuth(ClientAuth.NONE);
        builder.setMessage("TLS Server");
        builder.setTimeout(10 * 60 * 1000);
        builder.setPort(8443);

        Server server = builder.build();
        System.out.println("port: " + server.getPort());
        server.accept();
    }
}
