package com.tencent.kona.sun.security.ssl;

import com.tencent.kona.crypto.CryptoInsts;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

final class TLCPHandshakeHash implements HandshakeHash.TranscriptHash {

    private final HandshakeHash.TranscriptHash transcriptHash;
    private final ByteArrayOutputStream baos;

    TLCPHandshakeHash() {
        MessageDigest md = null;
        try {
            md = CryptoInsts.getMessageDigest("SM3");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SM3 is not supported", e);
        }

        if (md instanceof Cloneable) {
            transcriptHash = new HandshakeHash.CloneableHash(md);
            this.baos = new ByteArrayOutputStream();
        } else {
            transcriptHash = new HandshakeHash.NonCloneableHash(md);
            this.baos = null;
        }
    }

    @Override
    public void update(byte[] input, int offset, int length) {
        transcriptHash.update(input, offset, length);
        if (baos != null) {
            baos.write(input, offset, length);
        }
    }

    @Override
    public byte[] digest() {
        return transcriptHash.digest();
    }

    @Override
    public byte[] archived() {
        if (baos != null) {
            return baos.toByteArray();
        } else {
            return transcriptHash.archived();
        }
    }
}
