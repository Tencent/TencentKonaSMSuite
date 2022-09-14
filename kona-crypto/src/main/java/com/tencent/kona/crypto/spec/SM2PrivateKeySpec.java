package com.tencent.kona.crypto.spec;

import com.tencent.kona.crypto.CryptoUtils;

import java.math.BigInteger;
import java.security.spec.ECPrivateKeySpec;

public class SM2PrivateKeySpec extends ECPrivateKeySpec {

    public SM2PrivateKeySpec(byte[] key, int offset, int length) {
        super(new BigInteger(CryptoUtils.copy(key, offset, length)),
                SM2ParameterSpec.instance());
    }

    public SM2PrivateKeySpec(byte[] key) {
        this(key, 0, key.length);
    }

    public SM2PrivateKeySpec(byte[] key, int offset) {
        this(key, offset, key.length - offset);
    }
}
