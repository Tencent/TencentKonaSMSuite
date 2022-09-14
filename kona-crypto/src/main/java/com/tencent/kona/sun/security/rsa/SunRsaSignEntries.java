/*
 * Copyright (c) 2003, 2020, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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

package com.tencent.kona.sun.security.rsa;

import com.tencent.kona.sun.security.util.SecurityProviderConstants;

import java.util.*;
import java.security.Provider;

/**
 * Defines the entries of the SunRsaSign provider.
 *
 * @author  Andreas Sterbenz
 */
public final class SunRsaSignEntries {

    private void add(Provider p, String type, String algo, String cn,
             List<String> aliases, HashMap<String, String> attrs) {
         services.add(new Provider.Service(p, type, algo, cn,
             aliases, attrs));
    }

    private void addA(Provider p, String type, String algo, String cn,
             HashMap<String, String> attrs) {
         services.add(new Provider.Service(p, type, algo, cn,
             SecurityProviderConstants.getAliases(algo), attrs));
    }

    // extend LinkedHashSet for consistency with SunEntries
    // used by sun.security.provider.VerificationProvider
    public SunRsaSignEntries(Provider p) {
        services = new LinkedHashSet<>(20, 0.9f);

        // start populating content using the specified provider
        // common attribute map
        HashMap<String, String> attrs = new HashMap<>(3);
        attrs.put("SupportedKeyClasses",
                "java.security.interfaces.RSAPublicKey" +
                "|java.security.interfaces.RSAPrivateKey");

        add(p, "KeyFactory", "RSA",
                "com.tencent.kona.sun.security.rsa.RSAKeyFactory$Legacy",
                SecurityProviderConstants.getAliases("PKCS1"), null);
        add(p, "KeyPairGenerator", "RSA",
                "com.tencent.kona.sun.security.rsa.RSAKeyPairGenerator$Legacy",
                SecurityProviderConstants.getAliases("PKCS1"), null);
        addA(p, "Signature", "MD2withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$MD2withRSA", attrs);
        addA(p, "Signature", "MD5withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$MD5withRSA", attrs);
        addA(p, "Signature", "SHA1withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA1withRSA", attrs);
        addA(p, "Signature", "SHA224withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA224withRSA", attrs);
        addA(p, "Signature", "SHA256withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA256withRSA", attrs);
        addA(p, "Signature", "SHA384withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA384withRSA", attrs);
        addA(p, "Signature", "SHA512withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA512withRSA", attrs);
        addA(p, "Signature", "SHA512/224withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA512_224withRSA", attrs);
        addA(p, "Signature", "SHA512/256withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA512_256withRSA", attrs);
        addA(p, "Signature", "SHA3-224withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA3_224withRSA", attrs);
        addA(p, "Signature", "SHA3-256withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA3_256withRSA", attrs);
        addA(p, "Signature", "SHA3-384withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA3_384withRSA", attrs);
        addA(p, "Signature", "SHA3-512withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA3_512withRSA", attrs);

        addA(p, "KeyFactory", "RSASSA-PSS",
                "com.tencent.kona.sun.security.rsa.RSAKeyFactory$PSS", attrs);
        addA(p, "KeyPairGenerator", "RSASSA-PSS",
                "com.tencent.kona.sun.security.rsa.RSAKeyPairGenerator$PSS", attrs);
        addA(p, "Signature", "RSASSA-PSS",
                "com.tencent.kona.sun.security.rsa.RSAPSSSignature", attrs);
        addA(p, "AlgorithmParameters", "RSASSA-PSS",
                "com.tencent.kona.sun.security.rsa.PSSParameters", null);
    }

    public Iterator<Provider.Service> iterator() {
        return services.iterator();
    }

    private LinkedHashSet<Provider.Service> services;

    public static void putEntries(Provider p) {
        p.put("SupportedKeyClasses",
                "java.security.interfaces.RSAPublicKey|java.security.interfaces.RSAPrivateKey");

        p.put("KeyFactory.RSA",
                "com.tencent.kona.sun.security.rsa.RSAKeyFactory$Legacy");
        p.put("KeyPairGenerator.RSA",
                "com.tencent.kona.sun.security.rsa.RSAKeyPairGenerator$Legacy");
        p.put("Signature.MD2withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$MD2withRSA");
        p.put("Signature.MD5withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$MD5withRSA");
        p.put("Signature.SHA1withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA1withRSA");
        p.put("Signature.SHA224withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA224withRSA");
        p.put("Signature.SHA256withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA256withRSA");
        p.put("Signature.SHA384withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA384withRSA");
        p.put("Signature.SHA512withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA512withRSA");
        p.put("Signature.SHA512/224withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA512_224withRSA");
        p.put("Signature.SHA512/256withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA512_256withRSA");
        p.put("Signature.SHA3-224withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA3_224withRSA");
        p.put("Signature.SHA3-256withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA3_256withRSA");
        p.put("Signature.SHA3-384withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA3_384withRSA");
        p.put("Signature.SHA3-512withRSA",
                "com.tencent.kona.sun.security.rsa.RSASignature$SHA3_512withRSA");

        p.put("KeyFactory.RSASSA-PSS",
                "com.tencent.kona.sun.security.rsa.RSAKeyFactory$PSS");
        p.put("KeyPairGenerator.RSASSA-PSS",
                "com.tencent.kona.sun.security.rsa.RSAKeyPairGenerator$PSS");
        p.put("Signature.RSASSA-PSS",
                "com.tencent.kona.sun.security.rsa.RSAPSSSignature");
        p.put("AlgorithmParameters.RSASSA-PSS",
                "com.tencent.kona.sun.security.rsa.PSSParameters");
    }
}
