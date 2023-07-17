package com.tencent.kona.crypto.provider;

import java.security.DigestException;
import java.security.MessageDigest;

import static com.tencent.kona.crypto.util.Constants.SM3_DIGEST_LEN;

public final class SM3MessageDigest extends MessageDigest implements Cloneable {

    private SM3Engine engine = new SM3Engine();

    public SM3MessageDigest() {
        super("SM3");
    }

    @Override
    protected int engineGetDigestLength() {
        return SM3_DIGEST_LEN;
    }

    @Override
    protected void engineUpdate(byte input) {
        engine.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int length) {
        engine.update(input, offset, length);
    }

    @Override
    protected byte[] engineDigest() {
        byte[] digest = new byte[SM3_DIGEST_LEN];
        engine.doFinal(digest);
        return digest;
    }

    @Override
    protected int engineDigest(byte[] buf, int offset, int length)
            throws DigestException {
        if (length != SM3_DIGEST_LEN) {
            throw new DigestException("THe length must be 32-bytes");
        }

        engine.doFinal(buf, offset);
        return SM3_DIGEST_LEN;
    }

    @Override
    protected void engineReset() {
        engine.reset();
    }

    public Object clone() throws CloneNotSupportedException {
        SM3MessageDigest clone = (SM3MessageDigest) super.clone();
        clone.engine = engine.clone();
        return clone;
    }
}
