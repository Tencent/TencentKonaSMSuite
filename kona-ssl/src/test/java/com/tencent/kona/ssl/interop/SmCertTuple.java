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
