package com.tencent.kona.sun.security.x509;

import com.tencent.kona.crypto.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

/**
 * The test for AlgorithmId.
 */
public class AlgorithmIdTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testGetAlgorithm() throws Exception {
        checkOid("SM2", "1.2.156.10197.1.301");
        checkOid("SM3", "1.2.156.10197.1.401");
        checkOid("SM3withSM2", "1.2.156.10197.1.501");
    }

    private void checkOid(String name, String oid)
            throws NoSuchAlgorithmException {
        AlgorithmId algorithmId = AlgorithmId.get(name);
        Assertions.assertEquals(oid, algorithmId.getOID().toString());
    }
}
