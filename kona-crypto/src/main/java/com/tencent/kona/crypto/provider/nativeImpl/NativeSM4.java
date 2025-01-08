/*
 * Copyright (C) 2024, 2025, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. THL A29 Limited designates
 * this particular file as subject to the "Classpath" exception as provided
 * in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package com.tencent.kona.crypto.provider.nativeImpl;

import javax.crypto.AEADBadTagException;
import java.util.Objects;

import static com.tencent.kona.crypto.provider.nativeImpl.NativeCrypto.OPENSSL_SUCCESS;
import static com.tencent.kona.crypto.provider.nativeImpl.NativeCrypto.nativeCrypto;
import static com.tencent.kona.crypto.util.Constants.*;

/**
 * The SM4 native implementation.
 */
abstract class NativeSM4 extends NativeRef {

    final boolean encrypt;
    final Mode mode;
    final boolean padding;
    final byte[] key;
    byte[] iv;

    NativeSM4(boolean encrypt, Mode mode, boolean padding, byte[] key, byte[] iv) {
        super(createCtx(encrypt, mode, padding, key, iv));

        this.encrypt = encrypt;
        this.mode = mode;
        this.padding = padding;
        this.key = key;
        this.iv = iv;
    }

    private static long createCtx(boolean encrypt, Mode mode, boolean padding,
            byte[] key, byte[] iv) {
        if (mode == null) {
            throw new IllegalStateException("mode cannot be null");
        }

        if (key == null || key.length != SM4_KEY_SIZE) {
            throw new IllegalStateException("key must be 16-bytes");
        }

        if (mode == Mode.CBC || mode == Mode.CTR || mode == Mode.GCM) {
            if (iv == null) {
                throw new IllegalStateException("iv cannot be null");
            }

            if (mode == Mode.GCM) {
                if (iv.length != SM4_GCM_IV_LEN) {
                    throw new IllegalStateException("iv for GCM mode must be 12-bytes");
                }
            } else {
                if (iv.length != SM4_IV_LEN) {
                    throw new IllegalStateException("iv must be 16-bytes");
                }
            }
        } else {
            if (iv != null) {
                throw new IllegalStateException("iv is unnecessary");
            }
        }

        return nativeCrypto().sm4CreateCtx(encrypt, mode.name, padding, key, iv);
    }

    byte[] update(byte[] data) {
        Objects.requireNonNull(data);

        byte[] result = pointer == 0
                ? null
                : nativeCrypto().sm4Update(pointer, data);
        if (result == null) {
            throw new IllegalStateException("SM4 update operation failed");
        }
        return result;
    }

    byte[] doFinal() {
        byte[] result = pointer == 0
                ? null
                : nativeCrypto().sm4Final(pointer, key, iv);
        if (result == null) {
            throw new IllegalStateException("SM4 final operation failed");
        }
        return result;
    }

    byte[] doFinal(byte[] data) {
        Objects.requireNonNull(data);

        byte[] lastOut = update(data);
        byte[] finalOut = doFinal();
        byte[] out = new byte[lastOut.length + finalOut.length];
        System.arraycopy(lastOut, 0, out, 0, lastOut.length);
        System.arraycopy(finalOut, 0, out, lastOut.length, finalOut.length);
        return out;
    }

    @Override
    public void close() {
        if (pointer != 0) {
            nativeCrypto().sm4FreeCtx(pointer);
            super.close();
        }
    }

    final static class SM4CBC extends NativeSM4 {

        SM4CBC(boolean encrypt, boolean padding, byte[] key, byte[] iv) {
            super(encrypt, Mode.CBC, padding, key, iv);
        }
    }

    final static class SM4CTR extends NativeSM4 {

        SM4CTR(boolean encrypt, byte[] key, byte[] iv) {
            super(encrypt, Mode.CTR, false, key, iv);
        }
    }

    final static class SM4ECB extends NativeSM4 {

        SM4ECB(boolean encrypt, boolean padding, byte[] key) {
            super(encrypt, Mode.ECB, padding, key, null);
        }

        void processBlock(byte[] in, int inOff, byte[] out, int outOff) {
            byte[] inBlock = new byte[SM4_BLOCK_SIZE];
            System.arraycopy(in, inOff, inBlock, 0, SM4_BLOCK_SIZE);
            byte[] outBlock = update(inBlock);

            System.arraycopy(outBlock, 0, out, outOff, outBlock.length);
        }
    }

    static class SM4GCM extends NativeSM4 {

        private final boolean encrypt;

        SM4GCM(boolean encrypt, byte[] key, byte[] iv) {
            super(encrypt, Mode.GCM, false, key, iv);
            this.encrypt = encrypt;
        }

        void updateAAD(byte[] aad) {
            Objects.requireNonNull(aad);

            if (pointer == 0
                    || nativeCrypto().sm4GCMUpdateAAD(pointer, aad) != OPENSSL_SUCCESS){
                throw new IllegalStateException("SM4 updateAAD operation failed");
            }
        }

        byte[] doFinal() {
            byte[] result = pointer == 0
                    ? null
                    : nativeCrypto().sm4Final(pointer, null, null);
            if (result == null) {
                throw new IllegalStateException(
                        new AEADBadTagException("Tag is incorrect"));
            }
            return result;
        }

        void setIV(byte[] iv) {
            Objects.requireNonNull(iv);

            if (pointer == 0
                    || nativeCrypto().sm4GCMSetIV(pointer, iv) != OPENSSL_SUCCESS) {
                throw new IllegalStateException("SM4 setting IV operation failed");
            }

            this.iv = iv;
        }

        byte[] getTag() {
            byte[] tag = new byte[SM4_GCM_TAG_LEN];
            if (pointer == 0
                    || nativeCrypto().sm4GCMProcTag(pointer, tag) != OPENSSL_SUCCESS) {
                throw new IllegalStateException("SM4GCM getTag operation failed");
            }
            return tag;
        }

        void setTag(byte[] tag) {
            if (tag == null || tag.length != SM4_GCM_TAG_LEN) {
                throw new IllegalArgumentException("Tag must be 16-bytes");
            }

            if (pointer == 0
                    || nativeCrypto().sm4GCMProcTag(pointer, tag) != OPENSSL_SUCCESS) {
                throw new IllegalStateException("SM4GCM setTag operation failed");
            }
        }

        byte[] doFinal(byte[] data) {
            return encrypt ? encDoFinal(data) : decDoFinal(data);
        }

        private byte[] encDoFinal(byte[] data) {
            Objects.requireNonNull(data);

            byte[] lastOut = update(data);
            byte[] finalOut = doFinal();
            byte[] tag = getTag();

            byte[] out = new byte[lastOut.length + finalOut.length + tag.length];
            System.arraycopy(lastOut, 0, out, 0, lastOut.length);
            System.arraycopy(finalOut, 0, out, lastOut.length, finalOut.length);
            System.arraycopy(tag, 0, out, lastOut.length + finalOut.length, tag.length);
            return out;
        }

        private byte[] decDoFinal(byte[] data) {
            if (data == null || data.length < SM4_GCM_TAG_LEN) {
                throw new IllegalArgumentException("data must not be less than 16-bytes");
            }

            byte[] tag;
            byte[] msg;
            if (data.length == SM4_GCM_TAG_LEN) {
                tag = data;
                msg = new byte[0];
            } else {
                tag = new byte[SM4_GCM_TAG_LEN];
                System.arraycopy(data, data.length - SM4_GCM_TAG_LEN, tag, 0, SM4_GCM_TAG_LEN);
                msg = new byte[data.length - SM4_GCM_TAG_LEN];
                System.arraycopy(data, 0, msg, 0, data.length - SM4_GCM_TAG_LEN);
            }

            byte[] plaintext = update(msg);

            // Check tag
            setTag(tag);
            try {
                doFinal();
            } catch (IllegalStateException e) {
                throw new IllegalStateException("Tag is incorrect");
            }

            return plaintext;
        }
    }
}
