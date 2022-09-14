package com.tencent.kona.crypto.spec;

import com.tencent.kona.crypto.CryptoUtils;

import java.security.spec.ECPublicKeySpec;

public class SM2PublicKeySpec extends ECPublicKeySpec {

    public SM2PublicKeySpec(byte[] key, int offset, int length) {
        super(CryptoUtils.pubKeyPoint(CryptoUtils.copy(key, offset, length)),
                SM2ParameterSpec.instance());
    }

    public SM2PublicKeySpec(byte[] key) {
        this(key, 0, key.length);
    }

    public SM2PublicKeySpec(byte[] key, int offset) {
        this(key, offset, key.length - offset);
    }
}
