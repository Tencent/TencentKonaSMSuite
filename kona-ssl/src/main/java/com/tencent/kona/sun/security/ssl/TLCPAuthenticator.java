package com.tencent.kona.sun.security.ssl;

import com.tencent.kona.sun.security.ssl.Authenticator.SSLAuthenticator;
import com.tencent.kona.sun.security.ssl.Authenticator.MAC;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

final class TLCPAuthenticator {

    static class TLCP11Authenticator extends SSLAuthenticator {

        // Block size of TLCP:
        // sequence number(8) + record type(1) + protocol version(2) + record length(2)
        private static final int BLOCK_SIZE = 13;

        TLCP11Authenticator(ProtocolVersion protocolVersion) {
            super(new byte[BLOCK_SIZE]);
            block[9] = protocolVersion.major;
            block[10] = protocolVersion.minor;
        }

        @Override
        byte[] acquireAuthenticationBytes(
                byte type, int length, byte[] sequence) {
            byte[] ad = block.clone();
            if (sequence != null) {
                if (sequence.length != 8) {
                    throw new RuntimeException(
                            "Insufficient explicit sequence number bytes");
                }

                System.arraycopy(sequence, 0, ad, 0, sequence.length);
            } else {    // Otherwise, use the implicit sequence number.
                // Increase the implicit sequence number in the block array.
                increaseSequenceNumber();
            }

            ad[8] = type;
            ad[11] = (byte) (length >> 8);
            ad[12] = (byte) (length);

            return ad;
        }
    }

    static final class TLCP11Mac extends TLCP11Authenticator implements MAC {

        private final MacImpl macImpl;

        TLCP11Mac(ProtocolVersion protocolVersion,
                  CipherSuite.MacAlg macAlg, SecretKey key) throws NoSuchAlgorithmException,
                InvalidKeyException {
            super(protocolVersion);
            this.macImpl = new MacImpl(protocolVersion, macAlg, key);
        }

        @Override
        public CipherSuite.MacAlg macAlg() {
            return macImpl.macAlg;
        }

        @Override
        public byte[] compute(byte type, ByteBuffer bb,
                byte[] sequence, boolean isSimulated) {
            return macImpl.compute(type, bb, sequence, isSimulated);
        }
    }

    static final long toLong(byte[] recordEnS) {
        if (recordEnS != null && recordEnS.length == 8) {
            return ((recordEnS[0] & 0xFFL) << 56) |
                   ((recordEnS[1] & 0xFFL) << 48) |
                   ((recordEnS[2] & 0xFFL) << 40) |
                   ((recordEnS[3] & 0xFFL) << 32) |
                   ((recordEnS[4] & 0xFFL) << 24) |
                   ((recordEnS[5] & 0xFFL) << 16) |
                   ((recordEnS[6] & 0xFFL) <<  8) |
                    (recordEnS[7] & 0xFFL);
        }

        return -1L;
    }
}
