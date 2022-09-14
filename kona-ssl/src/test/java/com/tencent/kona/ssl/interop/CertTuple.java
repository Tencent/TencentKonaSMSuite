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

import java.util.Objects;

/*
 * A tuple for carrying certificates.
 */
public class CertTuple {

    public static final Cert[] EMPTY = new Cert[0];

    // Trusted CAs
    public final Cert[] trustedCerts;

    // End entity certificates
    public final Cert[] endEntityCerts;

    public CertTuple(Cert[] trustedCerts, Cert[] endEntityCerts) {
        Objects.requireNonNull(trustedCerts);
        Objects.requireNonNull(endEntityCerts);

        this.trustedCerts = trustedCerts;
        this.endEntityCerts = endEntityCerts;
    }

    public CertTuple(Cert trustedCert, Cert endEntityCert) {
        Objects.requireNonNull(trustedCert);
        Objects.requireNonNull(endEntityCert);

        this.trustedCerts = new Cert[] { trustedCert };
        this.endEntityCerts = new Cert[] { endEntityCert };
    }

    public Cert trustedCert() {
        return trustedCerts.length == 0 ? null : trustedCerts[0];
    }

    public Cert endEntityCert() {
        return endEntityCerts[0];
    }

    public Cert altEndEntityCert() {
        return endEntityCerts.length >= 2 ? endEntityCerts[1] : null;
    }

    public Cert signEndEntityCert() {
        return endEntityCert();
    }

    public Cert encEndEntityCert() {
        return altEndEntityCert();
    }

    @Override
    public String toString() {
        return Utilities.join(Utilities.PARAM_DELIMITER,
                "trustedCerts=" + Utilities.join(trustedCerts),
                "endEntityCerts=" + Utilities.join(endEntityCerts));
    }
}
