/*
 * Copyright (c) 2006, 2022, Oracle and/or its affiliates. All rights reserved.
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

package com.tencent.kona.sun.security.ec;

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.crypto.spec.RFC5915EncodedKeySpec;
import com.tencent.kona.jdk.internal.misc.SharedSecretsUtil;
import com.tencent.kona.sun.security.util.ArrayUtil;
import com.tencent.kona.sun.security.util.DerOutputStream;
import com.tencent.kona.sun.security.util.DerValue;
import com.tencent.kona.sun.security.util.ECUtil;
import com.tencent.kona.sun.security.x509.AlgorithmId;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyRep;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

/**
 * EC private key implementation in compliant with RFC 5915.
 *
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
 *   privateKey     OCTET STRING,
 *   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *   publicKey  [1] BIT STRING OPTIONAL
 * }
 */
public final class RFC5915Key implements ECPrivateKey {

    /* The algorithm information (name, parameters, etc). */
    private AlgorithmId algid;

    /* The key bytes, without the algorithm information */
    private byte[] key;

    /* The encoded for the key. Created on demand by encode(). */
    private byte[] encodedKey;

    /* The version for this key */
    private static final int V1 = 1;

    private BigInteger s;       // private value
    private byte[] arrayS;      // private value as a little-endian array

    private ECParameterSpec params;

    /**
     * Another constructor. Constructors in subclasses that create a new key
     * from an encoded byte array require this. We do not assign this
     * encoding to {@link #encodedKey} directly.
     *
     * This method is also used by {@link #parseKey} to create a raw key.
     */
    RFC5915Key(byte[] input) throws InvalidKeyException {
        decode(new ByteArrayInputStream(input));
        parseKeyBits();
    }

    private void decode(InputStream is) throws InvalidKeyException {
        DerValue val = null;
        try {
            val = new DerValue(is);
            if (val.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("invalid key format");
            }

            int version = val.data.getInteger();
            if (version != V1) {
                throw new InvalidKeyException("unknown version: " + version);
            }
            key = val.data.getOctetString();

            DerValue next;
            if (val.data.available() == 0) {
                return;
            }
            next = val.data.getDerValue();
            algid = new AlgorithmId(AlgorithmId.EC_oid, next.data.getDerValue());

            // Just ignore public key
            if (next.isContextSpecific((byte)0)) {
                if (val.data.available() == 0) {
                    return;
                }
                next = val.data.getDerValue();
            }

            if (next.isContextSpecific((byte)1)) {
                if (val.data.available() == 0) {
                    return;
                }
            }
            throw new InvalidKeyException("Extra bytes");
        } catch (IOException e) {
            throw new InvalidKeyException("IOException : " + e.getMessage());
        } finally {
            if (val != null) {
                val.clear();
            }
        }
    }

    RFC5915Key(BigInteger s, ECParameterSpec params)
            throws InvalidKeyException {
        this.s = s;
        this.params = params;
        makeEncoding(s);
    }

    private void makeEncoding(BigInteger s) throws InvalidKeyException {
        byte[] sArr = s.toByteArray();
        // convert to fixed-length array
        int numOctets = (params.getOrder().bitLength() + 7) / 8;
        byte[] sOctets = new byte[numOctets];
        int inPos = Math.max(sArr.length - sOctets.length, 0);
        int outPos = Math.max(sOctets.length - sArr.length, 0);
        int length = Math.min(sArr.length, sOctets.length);
        System.arraycopy(sArr, inPos, sOctets, outPos, length);
        Arrays.fill(sArr, (byte) 0);

        DerOutputStream out = new DerOutputStream();
        out.putInteger(1); // version 1
        out.putOctetString(sOctets);
        Arrays.fill(sOctets, (byte) 0);
        DerValue val = DerValue.wrap(DerValue.tag_Sequence, out);
        key = val.toByteArray();
        val.clear();
    }

    RFC5915Key(byte[] s, ECParameterSpec params)
            throws InvalidKeyException {
        this.arrayS = s.clone();
        this.params = params;
        makeEncoding(s);
    }

    private void makeEncoding(byte[] s) throws InvalidKeyException {
        DerOutputStream out = new DerOutputStream();
        out.putInteger(1); // version 1
        byte[] privBytes = s.clone();
        ArrayUtil.reverse(privBytes);
        out.putOctetString(privBytes);
        Arrays.fill(privBytes, (byte) 0);
        DerValue val = DerValue.wrap(DerValue.tag_Sequence, out);
        key = val.toByteArray();
        val.clear();
    }

    /**
     * Construct RFC 5915 subject public key from a DER encoding.  If a
     * security provider supports the key algorithm with a specific class,
     * a PrivateKey from the provider is returned.  Otherwise, a raw
     * RFC5915Key object is returned.
     *
     * <P>This mechanism guarantees that keys (and algorithms) may be
     * freely manipulated and transferred, without risk of losing
     * information.  Also, when a key (or algorithm) needs some special
     * handling, that specific need can be accommodated.
     *
     * @param encoded the DER-encoded SubjectPublicKeyInfo value
     * @exception IOException on data format errors
     */
    public static PrivateKey parseKey(byte[] encoded) throws IOException {
        try {
            RFC5915Key rawKey = new RFC5915Key(encoded);
            byte[] internal = rawKey.getEncodedInternal();
            RFC5915EncodedKeySpec rfc5915KeySpec = new RFC5915EncodedKeySpec(internal);
            PrivateKey result = null;
            try {
                result = CryptoInsts.getKeyFactory("EC").generatePrivate(rfc5915KeySpec);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                // Ignore and return raw key
                result = rawKey;
            } finally {
                if (result != rawKey) {
                    rawKey.clear();
                }
                SharedSecretsUtil.secSpecClearEncodedKeySpec(rfc5915KeySpec);
            }
            return result;
        } catch (InvalidKeyException e) {
            throw new IOException("corrupt private key", e);
        }
    }

    /**
     * Returns the algorithm to be used with this key.
     */
    public String getAlgorithm() {
        return "EC";
    }

    /**
     * Returns the DER-encoded form of the key as a byte array,
     * or {@code null} if an encoding error occurs.
     */
    public byte[] getEncoded() {
        return getEncodedInternal().clone();
    }

    /**
     * Returns the format for this key: "RFC5915"
     */
    public String getFormat() {
        return "RFC5915";
    }

    private void parseKeyBits() throws InvalidKeyException {
        byte[] clonedKey = key.clone();
        ArrayUtil.reverse(clonedKey);
        arrayS = clonedKey;

        AlgorithmParameters algParams = this.algid.getParameters();
        if (algParams == null) {
            throw new InvalidKeyException("EC domain parameters must be "
                + "encoded in the algorithm identifier");
        }
        try {
            params = algParams.getParameterSpec(ECParameterSpec.class);
        } catch (InvalidParameterSpecException e) {
            throw new InvalidKeyException("Invalid EC private key", e);
        }
    }

    // see JCA doc
    public BigInteger getS() {
        if (s == null) {
            byte[] arrCopy = arrayS.clone();
            ArrayUtil.reverse(arrCopy);
            s = new BigInteger(1, arrCopy);
            Arrays.fill(arrCopy, (byte)0);
        }
        return s;
    }

    public byte[] getArrayS() {
        if (arrayS == null) {
            arrayS = ECUtil.sArray(getS(), params);
        }
        return arrayS.clone();
    }

    // see JCA doc
    public ECParameterSpec getParams() {
        return params;
    }

    /**
     * DER-encodes this key as a byte array stored inside this object
     * and return it.
     *
     * @return the encoding, or null if there is an I/O error.
     */
    private synchronized byte[] getEncodedInternal() {
        if (encodedKey == null) {
            DerOutputStream tmp = new DerOutputStream();
            tmp.putInteger(V1);
            tmp.putOctetString(key);
            DerValue out = DerValue.wrap(DerValue.tag_Sequence, tmp);
            encodedKey = out.toByteArray();
            out.clear();
        }
        return encodedKey;
    }

    private Object writeReplace() throws java.io.ObjectStreamException {
        return new KeyRep(KeyRep.Type.PRIVATE,
                getAlgorithm(),
                getFormat(),
                getEncodedInternal());
    }

    /**
     * We used to serialize a RFC5915Key as itself (instead of a KeyRep).
     */
    private void readObject(ObjectInputStream stream) throws IOException {
        try {
            decode(stream);
        } catch (InvalidKeyException e) {
            throw new IOException("deserialized key is invalid: " +
                    e.getMessage());
        }
    }

    /**
     * Compares two private keys. This returns false if the object with which
     * to compare is not of type <code>Key</code>.
     * Otherwise, the encoding of this key object is compared with the
     * encoding of the given key object.
     *
     * @param object the object with which to compare
     * @return {@code true} if this key has the same encoding as the
     *          object argument; {@code false} otherwise.
     */
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object instanceof RFC5915Key) {
            // time-constant comparison
            return MessageDigest.isEqual(
                    getEncodedInternal(),
                    ((RFC5915Key)object).getEncodedInternal());
        } else if (object instanceof Key) {
            // time-constant comparison
            byte[] otherEncoded = ((Key)object).getEncoded();
            try {
                return MessageDigest.isEqual(
                        getEncodedInternal(),
                        otherEncoded);
            } finally {
                if (otherEncoded != null) {
                    Arrays.fill(otherEncoded, (byte) 0);
                }
            }
        }
        return false;
    }

    /**
     * Calculates a hash code value for this object. Objects
     * which are equal will also have the same hashcode.
     */
    public int hashCode() {
        return Arrays.hashCode(getEncodedInternal());
    }

    public void clear() {
        if (encodedKey != null) {
            Arrays.fill(encodedKey, (byte)0);
        }
        Arrays.fill(key, (byte)0);
    }
}
