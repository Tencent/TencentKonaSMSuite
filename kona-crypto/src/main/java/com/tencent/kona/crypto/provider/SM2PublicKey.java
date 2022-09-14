package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.spec.SM2ParameterSpec;
import com.tencent.kona.crypto.CryptoUtils;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

public class SM2PublicKey implements ECPublicKey {

    private static final long serialVersionUID = 682873544399078680L;

    private final byte[] key;
    private final transient ECPoint w;

    public SM2PublicKey(byte[] key) {
        CryptoUtils.checkKey(key);

        this.key = key.clone();
        w = CryptoUtils.pubKeyPoint(key);
    }

    public SM2PublicKey(ECPoint w) {
        CryptoUtils.checkKey(w);

        this.w = w;
        key = CryptoUtils.pubKey(w);
    }

    public SM2PublicKey(ECPublicKey ecPublicKey) {
        this(ecPublicKey.getW());
    }

    @Override
    public String getAlgorithm() {
        return "SM2";
    }

    /**
     * Uncompressed EC point: 0x04||X||Y
     */
    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return key.clone();
    }

    @Override
    public ECPoint getW() {
        return w;
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
        SM2PublicKey that = (SM2PublicKey) o;
        return Arrays.equals(key, that.key);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(key);
    }
}
