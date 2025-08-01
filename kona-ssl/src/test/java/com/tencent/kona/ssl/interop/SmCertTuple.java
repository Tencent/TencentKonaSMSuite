/*
 * Copyright (C) 2022, 2023, Tencent. All rights reserved.
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

package com.tencent.kona.ssl.interop;

/*
 * A tuple for carrying SM certificates.
 */
public class SmCertTuple extends CertTuple {

    public SmCertTuple(Cert rootCA,
                       Cert signEndEntityCert, Cert encEndEntityCert, Cert intCA) {
        super(new Cert[] { rootCA },
                encEndEntityCert == null
                        ? new Cert[] { signEndEntityCert, intCA }
                        : new Cert[] { signEndEntityCert, encEndEntityCert, intCA });
    }

    public SmCertTuple(Cert rootCA,
                       Cert signEndEntityCert, Cert encEndEntityCert) {
        super(new Cert[] { rootCA },
                encEndEntityCert == null
                        ? new Cert[] { signEndEntityCert }
                        : new Cert[] { signEndEntityCert, encEndEntityCert });
    }

    public SmCertTuple(Cert signEndEntityCert, Cert encEndEntityCert) {
        super(EMPTY, new Cert[] { signEndEntityCert, encEndEntityCert });
    }

    public SmCertTuple(Cert rootCA) {
        super(new Cert[] { rootCA}, EMPTY);
    }

    public Cert getIntCA() {
        return endEntityCerts.length >= 2 ? endEntityCerts[2] : null;
    }
}
