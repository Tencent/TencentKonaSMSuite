package com.tencent.kona.crypto.spec;

import java.security.spec.EncodedKeySpec;

/**
 * An encoded EC private key in compliant with RFC 5915.
 *
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *   privateKey     OCTET STRING,
 *   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *   publicKey  [1] BIT STRING OPTIONAL
 * }
 */
public class RFC5915EncodedKeySpec extends EncodedKeySpec {

    public RFC5915EncodedKeySpec(byte[] encodedKey) {
        super(encodedKey);
    }

    @Override
    public String getFormat() {
        return "RFC5915";
    }
}
