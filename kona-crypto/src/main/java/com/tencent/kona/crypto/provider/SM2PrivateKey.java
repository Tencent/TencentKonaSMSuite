package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.spec.SM2ParameterSpec;
import com.tencent.kona.crypto.CryptoUtils;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;

public class SM2PrivateKey implements ECPrivateKey {

    private static final long serialVersionUID = 8891019868158427133L;

    private final BigInteger keyS;
    private final byte[] key;

    public SM2PrivateKey(byte[] key) {
        CryptoUtils.checkKey(key);

        keyS = CryptoUtils.toBigInt(key);
        this.key = CryptoUtils.priKey(keyS);
    }

    public SM2PrivateKey(BigInteger keyS) {
        CryptoUtils.checkKey(keyS);

        this.keyS = keyS;
        key = CryptoUtils.priKey(keyS);
    }

    public SM2PrivateKey(ECPrivateKey ecPrivateKey) {
        this(ecPrivateKey.getS());
    }

    @Override
    public String getAlgorithm() {
        return "SM2";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return key.clone();
    }

    @Override
    public BigInteger getS() {
        return keyS;
    }

    @Override
    public ECParameterSpec getParams() {
        return SM2ParameterSpec.instance();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        SM2PrivateKey that = (SM2PrivateKey) o;
        return Arrays.equals(key, that.key);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(key);
    }
}
