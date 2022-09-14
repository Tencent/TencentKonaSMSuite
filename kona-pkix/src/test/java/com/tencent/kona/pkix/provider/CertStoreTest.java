package com.tencent.kona.pkix.provider;

import com.tencent.kona.pkix.KonaPKIXProvider;
import com.tencent.kona.pkix.PKIXInsts;
import com.tencent.kona.pkix.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;

/**
 * The test for CertStore.
 */
public class CertStoreTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testGetCertStore() throws Exception {
        CertStore certStore = PKIXInsts.getCertStore("Collection",
                new CollectionCertStoreParameters());
        Assertions.assertTrue(certStore.getProvider() instanceof KonaPKIXProvider);
    }

    @Test
    public void testGetCertificates() throws Exception {
        testGetCertificates(
                "ee-rsarsa-rsarsa-rsarsa.crt",
                "intca-rsarsa-rsarsa.crt",
                "ca-rsarsa.crt");
        testGetCertificates(
                "ee-sm2sm2-sm2sm2-sm2sm2.crt",
                "intca-sm2sm2-sm2sm2.crt",
                "ca-sm2sm2.crt");
        testGetCertificates(
                "ee-p256ecdsa-p256ecdsa-p256ecdsa.crt",
                "intca-p256ecdsa-p256ecdsa.crt",
                "ca-p256ecdsa.crt");
    }

    private void testGetCertificates(String ee, String intCa, String ca)
            throws Exception {
        Collection<X509Certificate> certs = new HashSet<>();
        X509Certificate target = TestUtils.certAsFile(ee);
        certs.add(TestUtils.certAsFile(ee));
        certs.add(TestUtils.certAsFile(intCa));
        certs.add(TestUtils.certAsFile(ca));

        CertStore certStore = PKIXInsts.getCertStore("Collection",
                new CollectionCertStoreParameters(certs));

        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setCertificate(target);

        Collection<? extends Certificate> foundCerts
                = certStore.getCertificates(certSelector);
        Assertions.assertEquals(
                target.getSerialNumber(),
                ((X509Certificate) foundCerts.iterator().next())
                        .getSerialNumber());
    }
}
