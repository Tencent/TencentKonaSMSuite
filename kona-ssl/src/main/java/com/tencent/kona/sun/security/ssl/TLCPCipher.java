/*
 * Copyright (c) 2018, 2022, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.tencent.kona.sun.security.ssl;

import com.tencent.kona.crypto.CryptoInsts;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

final class TLCPCipher {

    static final class TLCPBlockReadCipherGenerator
            implements SSLCipher.ReadCipherGenerator {

        @Override
        public SSLCipher.SSLReadCipher createCipher(SSLCipher sslCipher,
                Authenticator authenticator, ProtocolVersion protocolVersion,
                String algorithm, Key key, AlgorithmParameterSpec params,
                SecureRandom random) throws GeneralSecurityException {
            return new BlockReadCipher(authenticator, protocolVersion,
                    sslCipher, algorithm, key, params, random);
        }

        static final class BlockReadCipher extends SSLCipher.SSLReadCipher {
            private final Cipher cipher;

            BlockReadCipher(Authenticator authenticator,
                    ProtocolVersion protocolVersion,
                    SSLCipher sslCipher, String algorithm,
                    Key key, AlgorithmParameterSpec params,
                    SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = CryptoInsts.getCipher(algorithm);
                if (params == null) {
                    params = new IvParameterSpec(new byte[sslCipher.ivSize]);
                }
                cipher.init(Cipher.DECRYPT_MODE, key, params, random);
            }

            @Override
            public Plaintext decrypt(byte contentType, ByteBuffer bb,
                    byte[] sequence) throws GeneralSecurityException {
                BadPaddingException reservedBPE = null;

                // sanity check length of the ciphertext
                Authenticator.MAC signer = (Authenticator.MAC)authenticator;
                int cipheredLength = bb.remaining();
                int tagLen = signer.macAlg().size;
                if (tagLen != 0) {
                    if (!sanityCheck(tagLen, cipheredLength)) {
                        reservedBPE = new BadPaddingException(
                                "ciphertext sanity check failed");
                    }
                }

                // decryption
                ByteBuffer pt;
                int pos;

                // Do in-place with the bb buffer if it's not read-only
                if (!bb.isReadOnly()) {
                    pt = bb.duplicate();
                    pos = bb.position();
                } else {
                    pt = ByteBuffer.allocate(cipheredLength);
                    pos = 0;
                }
                try {
                    if (cipheredLength != cipher.update(bb, pt)) {
                        // catch BouncyCastle buffering error
                        throw new RuntimeException(
                                "Unexpected number of plaintext bytes");
                    }
                } catch (ShortBufferException sbe) {
                    // catch BouncyCastle buffering error
                    throw new RuntimeException("Cipher buffering error in " +
                        "JCE provider " + cipher.getProvider().getName(), sbe);
                }

                if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                    SSLLogger.fine(
                            "Padded plaintext after DECRYPTION",
                            pt.duplicate().position(pos));
                }

                // Ignore the explicit nonce.
                int blockSize = cipher.getBlockSize();
                pos += blockSize;
                pt.position(pos);

                // remove the block padding
                try {
                    SSLCipher.removePadding(pt, tagLen, blockSize, protocolVersion);
                } catch (BadPaddingException bpe) {
                    if (reservedBPE == null) {
                        reservedBPE = bpe;
                    }
                }

                // Requires message authentication code for null, stream and
                // block cipher suites.
                try {
                    if (tagLen != 0) {
                        SSLCipher.checkCBCMac(signer, pt,
                                contentType, cipheredLength, sequence);
                    } else {
                        authenticator.increaseSequenceNumber();
                    }
                } catch (BadPaddingException bpe) {
                    if (reservedBPE == null) {
                        reservedBPE = bpe;
                    }
                }

                // Is it a failover?
                if (reservedBPE != null) {
                    throw reservedBPE;
                }

                return new Plaintext(contentType,
                        ProtocolVersion.NONE.major, ProtocolVersion.NONE.minor,
                        -1, -1L, pt.slice());
            }

            @Override
            void dispose() {
                if (cipher != null) {
                    try {
                        cipher.doFinal();
                    } catch (Exception e) {
                        // swallow all types of exceptions.
                    }
                }
            }

            @Override
            int estimateFragmentSize(int packetSize, int headerSize) {
                int macLen = ((Authenticator.MAC)authenticator).macAlg().size;

                // No padding for a maximum fragment.
                //
                // 1 byte padding length field: 0x00
                int nonceSize = cipher.getBlockSize();
                return packetSize - headerSize - nonceSize - macLen - 1;
            }

            /**
             * Sanity check the length of a fragment before decryption.
             *
             * In CBC mode, check that the fragment length is one or multiple
             * times of the block size of the cipher suite, and is at least
             * one (one is the smallest size of padding in CBC mode) bigger
             * than the tag size of the MAC algorithm except the explicit IV
             * size for TLS 1.1 or later.
             *
             * In non-CBC mode, check that the fragment length is not less than
             * the tag size of the MAC algorithm.
             *
             * @return true if the length of a fragment matches above
             *         requirements
             */
            private boolean sanityCheck(int tagLen, int fragmentLen) {
                int blockSize = cipher.getBlockSize();
                if ((fragmentLen % blockSize) == 0) {
                    int minimal = tagLen + 1;
                    minimal = Math.max(minimal, blockSize);
                    minimal += blockSize;

                    return (fragmentLen >= minimal);
                }

                return false;
            }
        }
    }

    static final class TLCPBlockWriteCipherGenerator
            implements SSLCipher.WriteCipherGenerator {

        @Override
        public SSLCipher.SSLWriteCipher createCipher(SSLCipher sslCipher,
                Authenticator authenticator, ProtocolVersion protocolVersion,
                String algorithm, Key key, AlgorithmParameterSpec params,
                SecureRandom random) throws GeneralSecurityException {
            return new BlockWriteCipher(authenticator, protocolVersion,
                    sslCipher, algorithm, key, params, random);
        }

        static final class BlockWriteCipher extends SSLCipher.SSLWriteCipher {
            private final Cipher cipher;
            private final SecureRandom random;

            BlockWriteCipher(Authenticator authenticator,
                    ProtocolVersion protocolVersion,
                    SSLCipher sslCipher, String algorithm,
                    Key key, AlgorithmParameterSpec params,
                    SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = CryptoInsts.getCipher(algorithm);
                this.random = random;
                if (params == null) {
                    params = new IvParameterSpec(new byte[sslCipher.ivSize]);
                }
                cipher.init(Cipher.ENCRYPT_MODE, key, params, random);
            }

            @Override
            public int encrypt(byte contentType, ByteBuffer bb) {
                // To be unique and aware of overflow-wrap, sequence number
                // is used as the nonce_explicit of block cipher suites.
                int pos = bb.position();

                // add message authentication code
                Authenticator.MAC signer = (Authenticator.MAC)authenticator;
                if (signer.macAlg().size != 0) {
                    SSLCipher.addMac(signer, bb, contentType);
                } else {
                    authenticator.increaseSequenceNumber();
                }

                // DON'T WORRY, the nonce spaces are considered already.
                byte[] nonce = new byte[cipher.getBlockSize()];
                random.nextBytes(nonce);
                pos = pos - nonce.length;
                bb.position(pos);
                bb.put(nonce);
                bb.position(pos);

                int blockSize = cipher.getBlockSize();
                int len = SSLCipher.addPadding(bb, blockSize);
                bb.position(pos);

                if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                    SSLLogger.fine(
                            "Padded plaintext before ENCRYPTION",
                            bb.duplicate());
                }

                ByteBuffer dup = bb.duplicate();
                try {
                    if (len != cipher.update(dup, bb)) {
                        // catch BouncyCastle buffering error
                        throw new RuntimeException(
                                "Unexpected number of plaintext bytes");
                    }

                    if (bb.position() != dup.position()) {
                        throw new RuntimeException(
                                "Unexpected ByteBuffer position");
                    }
                } catch (ShortBufferException sbe) {
                    // catch BouncyCastle buffering error
                    throw new RuntimeException("Cipher buffering error in " +
                        "JCE provider " + cipher.getProvider().getName(), sbe);
                }

                return len;
            }

            @Override
            void dispose() {
                if (cipher != null) {
                    try {
                        cipher.doFinal();
                    } catch (Exception e) {
                        // swallow all types of exceptions.
                    }
                }
            }

            @Override
            int getExplicitNonceSize() {
                return cipher.getBlockSize();
            }

            @Override
            int calculateFragmentSize(int packetLimit, int headerSize) {
                int macLen = ((Authenticator.MAC)authenticator).macAlg().size;
                int blockSize = cipher.getBlockSize();
                int fragLen = packetLimit - headerSize - blockSize;
                fragLen -= (fragLen % blockSize);   // cannot hold a block
                // No padding for a maximum fragment.
                fragLen -= 1;       // 1 byte padding length field: 0x00
                fragLen -= macLen;
                return fragLen;
            }

            @Override
            int calculatePacketSize(int fragmentSize, int headerSize) {
                int macLen = ((Authenticator.MAC)authenticator).macAlg().size;
                int blockSize = cipher.getBlockSize();
                int paddedLen = fragmentSize + macLen + 1;
                if ((paddedLen % blockSize) != 0) {
                    paddedLen += blockSize - 1;
                    paddedLen -= paddedLen % blockSize;
                }

                return headerSize + blockSize + paddedLen;
            }

            @Override
            boolean isCBCMode() {
                return true;
            }
        }
    }

    static final class TLCPGcmReadCipherGenerator
            implements SSLCipher.ReadCipherGenerator {

        @Override
        public SSLCipher.SSLReadCipher createCipher(SSLCipher sslCipher,
                Authenticator authenticator,
                ProtocolVersion protocolVersion, String algorithm,
                Key key, AlgorithmParameterSpec params,
                SecureRandom random) throws GeneralSecurityException {
            return new GcmReadCipher(authenticator, protocolVersion, sslCipher,
                    algorithm, key, params, random);
        }

        static final class GcmReadCipher extends SSLCipher.SSLReadCipher {
            private final Cipher cipher;
            private final int tagSize;
            private final Key key;
            private final byte[] fixedIv;
            private final int recordIvSize;
            private final SecureRandom random;

            GcmReadCipher(Authenticator authenticator,
                    ProtocolVersion protocolVersion,
                    SSLCipher sslCipher, String algorithm,
                    Key key, AlgorithmParameterSpec params,
                    SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = CryptoInsts.getCipher(algorithm);
                this.tagSize = sslCipher.tagSize;
                this.key = key;
                this.fixedIv = ((IvParameterSpec)params).getIV();
                this.recordIvSize = sslCipher.ivSize - sslCipher.fixedIvSize;
                this.random = random;

                // DON'T initialize the cipher for AEAD!
            }

            @Override
            public Plaintext decrypt(byte contentType, ByteBuffer bb,
                    byte[] sequence) throws GeneralSecurityException {
                if (bb.remaining() < (recordIvSize + tagSize)) {
                    throw new BadPaddingException(
                        "Insufficient buffer remaining for AEAD cipher " +
                        "fragment (" + bb.remaining() + "). Needs to be " +
                        "more than or equal to IV size (" + recordIvSize +
                         ") + tag size (" + tagSize + ")");
                }

                // initialize the AEAD cipher for the unique IV
                byte[] iv = Arrays.copyOf(fixedIv,
                                    fixedIv.length + recordIvSize);
                bb.get(iv, fixedIv.length, recordIvSize);
                GCMParameterSpec spec = new GCMParameterSpec(tagSize * 8, iv);
                try {
                    cipher.init(Cipher.DECRYPT_MODE, key, spec, random);
                } catch (InvalidKeyException |
                            InvalidAlgorithmParameterException ikae) {
                    // unlikely to happen
                    throw new RuntimeException(
                                "invalid key or spec in GCM mode", ikae);
                }

                // update the additional authentication data
                byte[] aad = authenticator.acquireAuthenticationBytes(
                        contentType, bb.remaining() - tagSize,
                        sequence);
                cipher.updateAAD(aad);

                // DON'T decrypt the nonce_explicit for AEAD mode. The buffer
                // position has moved out of the nonce_explicit range.
                ByteBuffer pt;
                int len, pos;

                // Do in-place with the bb buffer if it's not read-only
                if (!bb.isReadOnly()) {
                    pt = bb.duplicate();
                    pos = bb.position();
                } else {
                    pt = ByteBuffer.allocate(bb.remaining());
                    pos = 0;
                }

                try {
                    len = cipher.doFinal(bb, pt);
                } catch (IllegalBlockSizeException ibse) {
                    // unlikely to happen
                    throw new RuntimeException(
                        "Cipher error in AEAD mode \"" + ibse.getMessage() +
                        " \"in JCE provider " + cipher.getProvider().getName());
                } catch (ShortBufferException sbe) {
                    // catch BouncyCastle buffering error
                    throw new RuntimeException("Cipher buffering error in " +
                        "JCE provider " + cipher.getProvider().getName(), sbe);
                }
                // reset the limit to the end of the decrypted data
                pt.position(pos);
                pt.limit(pos + len);

                if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                    SSLLogger.fine(
                            "Plaintext after DECRYPTION", pt.duplicate());
                }

                return new Plaintext(contentType,
                        ProtocolVersion.NONE.major, ProtocolVersion.NONE.minor,
                        -1, -1L, pt.slice());
            }

            @Override
            int estimateFragmentSize(int packetSize, int headerSize) {
                return packetSize - headerSize - recordIvSize - tagSize;
            }
        }
    }

    static final class TLCPGcmWriteCipherGenerator
            implements SSLCipher.WriteCipherGenerator {

        @Override
        public SSLCipher.SSLWriteCipher createCipher(SSLCipher sslCipher,
                Authenticator authenticator,
                ProtocolVersion protocolVersion, String algorithm,
                Key key, AlgorithmParameterSpec params,
                SecureRandom random) throws GeneralSecurityException {
            return new GcmWriteCipher(authenticator, protocolVersion, sslCipher,
                    algorithm, key, params, random);
        }

        private static final class GcmWriteCipher extends SSLCipher.SSLWriteCipher {
            private final Cipher cipher;
            private final int tagSize;
            private final Key key;
            private final byte[] fixedIv;
            private final int recordIvSize;
            private final SecureRandom random;

            GcmWriteCipher(Authenticator authenticator,
                    ProtocolVersion protocolVersion,
                    SSLCipher sslCipher, String algorithm,
                    Key key, AlgorithmParameterSpec params,
                    SecureRandom random) throws GeneralSecurityException {
                super(authenticator, protocolVersion);
                this.cipher = CryptoInsts.getCipher(algorithm);
                this.tagSize = sslCipher.tagSize;
                this.key = key;
                this.fixedIv = ((IvParameterSpec)params).getIV();
                this.recordIvSize = sslCipher.ivSize - sslCipher.fixedIvSize;
                this.random = random;

                // DON'T initialize the cipher for AEAD!
            }

            @Override
            public int encrypt(byte contentType,
                    ByteBuffer bb) {
                // To be unique and aware of overflow-wrap, sequence number
                // is used as the nonce_explicit of AEAD cipher suites.
                byte[] nonce = authenticator.sequenceNumber();

                // initialize the AEAD cipher for the unique IV
                byte[] iv = Arrays.copyOf(fixedIv,
                                            fixedIv.length + nonce.length);
                System.arraycopy(nonce, 0, iv, fixedIv.length, nonce.length);

                GCMParameterSpec spec = new GCMParameterSpec(tagSize * 8, iv);
                try {
                    cipher.init(Cipher.ENCRYPT_MODE, key, spec, random);
                } catch (InvalidKeyException |
                            InvalidAlgorithmParameterException ikae) {
                    // unlikely to happen
                    throw new RuntimeException(
                                "invalid key or spec in GCM mode", ikae);
                }

                // Update the additional authentication data, using the
                // implicit sequence number of the authenticator.
                byte[] aad = authenticator.acquireAuthenticationBytes(
                                        contentType, bb.remaining(), null);
                cipher.updateAAD(aad);

                // DON'T WORRY, the nonce spaces are considered already.
                bb.position(bb.position() - nonce.length);
                bb.put(nonce);

                // DON'T encrypt the nonce for AEAD mode.
                int len, pos = bb.position();
                if (SSLLogger.isOn && SSLLogger.isOn("plaintext")) {
                    SSLLogger.fine(
                            "Plaintext before ENCRYPTION",
                            bb.duplicate());
                }

                ByteBuffer dup = bb.duplicate();
                int outputSize = cipher.getOutputSize(dup.remaining());
                if (outputSize > bb.remaining()) {
                    // Need to expand the limit of the output buffer for
                    // the authentication tag.
                    //
                    // DON'T worry about the buffer's capacity, we have
                    // reserved space for the authentication tag.
                    bb.limit(pos + outputSize);
                }

                try {
                    len = cipher.doFinal(dup, bb);
                } catch (IllegalBlockSizeException |
                            BadPaddingException | ShortBufferException ibse) {
                    // unlikely to happen
                    throw new RuntimeException(
                            "Cipher error in AEAD mode in JCE provider " +
                            cipher.getProvider().getName(), ibse);
                }

                if (len != outputSize) {
                    throw new RuntimeException(
                            "Cipher buffering error in JCE provider " +
                            cipher.getProvider().getName());
                }

                return len + nonce.length;
            }

            @Override
            int getExplicitNonceSize() {
                return recordIvSize;
            }

            @Override
            int calculateFragmentSize(int packetLimit, int headerSize) {
                return packetLimit - headerSize - recordIvSize - tagSize;
            }

            @Override
            int calculatePacketSize(int fragmentSize, int headerSize) {
                return fragmentSize + headerSize + recordIvSize + tagSize;
            }
        }
    }
}
