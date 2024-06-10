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

import com.tencent.kona.crypto.CryptoUtils;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

/*
 * Utilities for JDK process peers.
 */
public class JdkProcUtils {

    public static final String PROP_HOST = "test.host";
    public static final String PROP_PORT = "test.port";

    public static final String PROP_SEC_PROPS_FILE = "java.security.properties";
    public static final String PROP_PROVIDER = "test.provider";
    public static final String PROP_KEYSTORE_TYPE = "test.keystore.type";
    public static final String PROP_TRUST_MANAGER_ALGO = "test.trust.manager.algo";
    public static final String PROP_KEY_MANAGER_ALGO = "test.key.manager.algo";
    public static final String PROP_CTX_PROTOCOL = "test.context.protocol";
    public static final String PROP_PROTOCOLS = "test.protocols";
    public static final String PROP_CIPHER_SUITES = "test.cipher.suites";
    public static final String PROP_TRUSTED_CERTS = "test.trusted.certs";
    public static final String PROP_EE_CERTS = "test.ee.certs";
    public static final String PROP_CLIENT_AUTH = "test.client.auth";
    public static final String PROP_SERVER_NAMES = "test.server.names";
    public static final String PROP_APP_PROTOCOLS = "test.app.protocols";
    public static final String PROP_NAMED_GROUPS = "test.named.groups";
    public static final String PROP_SIGNATURE_SCHEMES = "test.signature.schemes";
    public static final String PROP_MESSAGE = "test.message";
    public static final String PROP_READ_RESPONSE = "test.read.response";

    /*
     * Converts a Cert instance to a string, which contains the field values of
     * the Cert. The values are separated by comma.
     */
    public static String certToStr(Cert cert) {
        return Utilities.join(cert.keyAlgo, cert.sigAlgo, cert.hashAlgo,
                cert.certMaterials, cert.keyMaterials);
    }

    /*
     * Converts multiple Certs to a string. The value strings of the Certs are
     * separated by semicolon.
     */
    public static String certsToStr(Cert[] certs) {
        StringJoiner joiner = new StringJoiner(Utilities.PARAM_DELIMITER);
        for (Cert cert : certs) {
            joiner.add(certToStr(cert));
        }
        return joiner.toString();
    }

    /*
     * Converts a string, which contains the field values of a Cert,
     * to a Cert instance.
     */
    public static Cert strToCert(String certStr) {
        if (certStr == null || certStr.trim().isEmpty()) {
            return null;
        }

        String[] values = Utilities.split(certStr);
        String keyAlgo = values[0];
        String sigAlgo = values[1];
        String hashAlgo = values[2];
        String certMaterials = values[3];
        String keyMaterials = values.length == 5 ? values[4] : null;
        return new Cert(KeyAlgorithm.valueOf(keyAlgo),
                SignatureAlgorithm.valueOf(sigAlgo),
                HashAlgorithm.valueOf(hashAlgo), certMaterials, keyMaterials);
    }

    /*
     * Converts a string to multiple Certs.
     */
    public static Cert[] strToCerts(String certsStr) {
        String[] certStrs = Utilities.split(certsStr, Utilities.PARAM_DELIMITER);
        if (certStrs.length == 0) {
            return CertTuple.EMPTY;
        }

        List<Cert> certs = new ArrayList<>();
        for (String certStr : certStrs) {
            if (certStr != null && !certStr.isEmpty()) {
                Cert bufCert = strToCert(certStr);
                if (bufCert != null) {
                    certs.add(bufCert);
                }
            }
        }
        return certs.toArray(new Cert[0]);
    }

    public static CertTuple createCertTuple(String trustedCertsStr,
            String eeCertsStr) {
        Cert[] trustedCerts = strToCerts(trustedCertsStr);
        Cert[] eeCerts = strToCerts(eeCertsStr);
        return new CertTuple(trustedCerts, eeCerts);
    }

    /*
    * Executes java program.
    * It can redirect the output to a local file if necessary,
    * and will returns the process for later application.
    */
    public static Process java(Jdk jdk, List<String> options,
            Class<?> clazz, Map<String, String> props, Path outputPath)
            throws IOException {
        List<String> allOptions = new ArrayList<>();

        if (options != null) {
            allOptions.addAll(options);
        }

        if (CryptoUtils.isJdk11()) {
            allOptions.addAll(Utilities.JDK11_OPTIONS);
        } else if (CryptoUtils.isJdk17() || CryptoUtils.isJdk21()) {
            allOptions.addAll(Utilities.JDK17_OPTIONS);
        }

        ProcessBuilder pb = createProcessBuilder(
                jdk.getPath(), allOptions, Utilities.CLASSPATH, clazz, props);
        if (outputPath != null) {
            pb.redirectOutput(outputPath.toFile());
        }
        return pb.start();
    }

    private static ProcessBuilder createProcessBuilder(Path javaPath,
            List<String> options, String classpath, Class<?> clazz,
            Map<String, String> props) {
        List<String> cmds = new ArrayList<>();
        cmds.add(javaPath.toString());

        if (options != null) {
            cmds.addAll(options);
        }

        if (props != null) {
            for (Map.Entry<String, String> prop : props.entrySet()) {
                cmds.add("-D" + prop.getKey() + "=" + prop.getValue());
            }
        }

        cmds.add("-cp");
        cmds.add(classpath);
        cmds.add(clazz.getName());
        ProcessBuilder pb = new ProcessBuilder(cmds);
        pb.redirectErrorStream(true);
        return pb;
    }
}
