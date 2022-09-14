package com.tencent.kona.crypto.spec;

import javax.crypto.spec.SecretKeySpec;

public class SM4KeySpec extends SecretKeySpec {

    private static final long serialVersionUID = -621469601839652916L;

    public SM4KeySpec(byte[] key, int offset, int length) {
        super(key, offset, length, "SM4");
    }

    public SM4KeySpec(byte[] key) {
        this(key, 0, key.length);
    }

    public SM4KeySpec(byte[] key, int offset) {
        this(key, offset, key.length - offset);
    }
}
