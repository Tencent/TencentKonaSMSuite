/*
 * Copyright (c) 1997, 2025, Oracle and/or its affiliates. All rights reserved.
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

package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.util.Sweeper;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.security.MessageDigest;
import java.security.KeyRep;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Locale;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

import com.tencent.kona.sun.security.util.PBEUtil;

/**
 * This class represents a PBE key.
 *
 * @author Jan Luehe
 *
 */
final class PBEKey implements SecretKey {

    private static final long serialVersionUID = -2234768909660948176L;

    private byte[] key;

    private final String type;

    private final Sweeper sweeper = Sweeper.instance();

    /**
     * Creates a PBE key from a given PBE key specification.
     *
     * @param keytype the given PBE key specification
     */
    PBEKey(PBEKeySpec keySpec, String keytype, boolean useCleaner)
            throws InvalidKeySpecException {
        char[] passwd = keySpec.getPassword();
        if (passwd == null) {
            // Should allow an empty password.
            passwd = new char[0];
        }
        this.key = PBEUtil.encodePassword(passwd);
        Arrays.fill(passwd, '\0');
        type = keytype;

        // Use the cleaner to zero the key when no longer referenced
        if (useCleaner) {
            final byte[] k = this.key;
            sweeper.register(this,
                () -> Arrays.fill(k, (byte) 0x00));
        }
    }

    public byte[] getEncoded() {
        // The key is zeroized by finalize()
        // The reachability fence ensures finalize() isn't called early
        byte[] result = key.clone();
//        Reference.reachabilityFence(this);
        return result;
    }

    public String getAlgorithm() {
        return type;
    }

    public String getFormat() {
        return "RAW";
    }

    /**
     * Calculates a hash code value for the object.
     * Objects that are equal will also have the same hashcode.
     */
    public int hashCode() {
        return Arrays.hashCode(this.key)
                ^ getAlgorithm().toLowerCase(Locale.ENGLISH).hashCode();
    }

    public boolean equals(Object obj) {
        if (obj == this)
            return true;

        if (!(obj instanceof SecretKey))
            return false;

        SecretKey that = (SecretKey)obj;

        if (!(that.getAlgorithm().equalsIgnoreCase(type)))
            return false;

        byte[] thatEncoded = that.getEncoded();
        boolean ret = MessageDigest.isEqual(this.key, thatEncoded);
        Arrays.fill(thatEncoded, (byte)0x00);
        return ret;
    }

    /**
     * Clears the internal copy of the key.
     *
     */
    @Override
    public void destroy() {
        if (key != null) {
            Arrays.fill(key, (byte) 0x00);
            key = null;
        }
    }

    /**
     * Restores the state of this object from the stream.
     *
     * @param  s the {@code ObjectInputStream} from which data is read
     * @throws IOException if an I/O error occurs
     * @throws ClassNotFoundException if a serialized class cannot be loaded
     */
    private void readObject(java.io.ObjectInputStream s)
         throws java.io.IOException, ClassNotFoundException
    {
        s.defaultReadObject();
        if (key == null) {
            throw new InvalidObjectException(
                    "PBEKey couldn't be deserialized");
        }
        byte[] temp = key;
        key = temp.clone();
        Arrays.fill(temp, (byte)0x00);

        // Accept "\0" to signify "zero-length password with no terminator".
        if (!(key.length == 1 && key[0] == 0)) {
            for (int i = 0; i < key.length; i++) {
                if ((key[i] < '\u0020') || (key[i] > '\u007E')) {
                    throw new InvalidObjectException(
                            "PBEKey had non-ASCII chars");
                }
            }
        }

        // Use the cleaner to zero the key when no longer referenced
        final byte[] k = this.key;
        sweeper.register(this,
                () -> Arrays.fill(k, (byte) 0x00));
    }


    /**
     * Replace the PBE key to be serialized.
     *
     * @return the standard KeyRep object to be serialized
     *
     * @throws java.io.ObjectStreamException if a new object representing
     * this PBE key could not be created
     */
    private Object writeReplace() throws java.io.ObjectStreamException {
        return new KeyRep(KeyRep.Type.SECRET,
                getAlgorithm(),
                getFormat(),
                key);
    }
}
