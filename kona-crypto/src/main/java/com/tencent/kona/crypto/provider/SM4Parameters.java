/*
 * Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
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

package com.tencent.kona.crypto.provider;

import com.tencent.kona.sun.security.util.DerInputStream;
import com.tencent.kona.sun.security.util.DerOutputStream;
import com.tencent.kona.sun.security.util.DerValue;
import com.tencent.kona.sun.security.util.HexDumpEncoder;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import static com.tencent.kona.crypto.util.Constants.SM4_GCM_IV_LEN;
import static com.tencent.kona.crypto.util.Constants.SM4_GCM_TAG_LEN;
import static com.tencent.kona.crypto.util.Constants.SM4_IV_LEN;

/**
 * This class implements the parameter set for
 * - Feedback mode (RFC 5652)
 *   IV ::= OCTET STRING -- length is SM4 block size, exactly 16-bytes
 *
 * - GCM mode (RFC 5084)
 *   GCMParameters ::= SEQUENCE {
 *     sm4-iv      OCTET STRING, -- the size is 12 or 16-bytes
 *     sm4-tLen    SM4-GCM-ICVlen DEFAULT 12 }
 *   SM4-GCM-ICVlen ::= INTEGER (16)
 */
public final class SM4Parameters extends AlgorithmParametersSpi {

    private byte[] iv = null;
    private int tagLen = -1;

    private byte[] encoded;

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {
        if (!(paramSpec instanceof IvParameterSpec)
                && !(paramSpec instanceof  GCMParameterSpec)) {
            throw new InvalidParameterSpecException(
                    "Only IvParameterSpec and GCMParameterSpec are supported");
        }

        byte[] tmpIv;
        if (paramSpec instanceof IvParameterSpec) {
            tmpIv = ((IvParameterSpec) paramSpec).getIV();
            if (tmpIv.length != SM4_IV_LEN) {
                throw new InvalidParameterSpecException(
                        "IV must be 16-bytes: " + tmpIv.length);
            }
        } else {
            tmpIv = ((GCMParameterSpec) paramSpec).getIV();
            if (tmpIv.length != SM4_GCM_IV_LEN) {
                throw new InvalidParameterSpecException(
                        "GCM IV must be 12-bytes: " + tmpIv.length);
            }

            int tmpTagLen = ((GCMParameterSpec) paramSpec).getTLen() >> 3;
            if (tmpTagLen != SM4_GCM_TAG_LEN) {
                throw new InvalidParameterSpecException(
                        "GCM tag must be 16-bytes: " + tmpTagLen);
            }
            tagLen = tmpTagLen;
        }

        iv = tmpIv.clone();

    }

    @Override
    protected void engineInit(byte[] encoded) throws IOException {
        if (encoded == null || encoded.length == 0) {
            throw new IOException("Encoded parameters must be null or empty");
        }

        this.encoded = encoded.clone();
    }

    @Override
    protected void engineInit(byte[] encoded, String decodingMethod)
            throws IOException {
        if (decodingMethod != null
                && !decodingMethod.equalsIgnoreCase("ASN.1")) {
            throw new IllegalArgumentException("Only support ASN.1 format");
        }

        engineInit(encoded);
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(
            Class<T> paramSpec) throws InvalidParameterSpecException {
        if (IvParameterSpec.class.isAssignableFrom(paramSpec)) {
            try {
                decode();
            } catch (IOException e) {
                throw new InvalidParameterSpecException(
                        "Decode parameters failed: " + e.getMessage());
            }

            return paramSpec.cast(new IvParameterSpec(iv));
        } else if (GCMParameterSpec.class.isAssignableFrom(paramSpec)) {
            try {
                gcmDecode();
            } catch (IOException e) {
                throw new InvalidParameterSpecException(
                        "Decode GCM parameters failed: " + e.getMessage());
            }

            if (tagLen == SM4_GCM_TAG_LEN) {
                return paramSpec.cast(new GCMParameterSpec(tagLen, iv));
            } else throw new InvalidParameterSpecException(
                    "Invalid tag size: " + tagLen);
        } else {
            throw new InvalidParameterSpecException(
                    "Only IvParameterSpec and GCMParameterSpec are supported");
        }
    }

    private void decode() throws IOException {
        DerInputStream der = new DerInputStream(encoded);

        byte[] tmpIv = der.getOctetString();
        if (der.available() != 0) {
            throw new IOException("IV parsing error: extra data");
        }
        if (tmpIv.length != SM4_IV_LEN) {
            throw new IOException("IV is not 16-bytes: " + tmpIv.length);
        }

        iv = tmpIv;
    }

    private void gcmDecode() throws IOException {
        DerValue val = new DerValue(encoded);
        // check if IV or params
        if (val.tag == DerValue.tag_Sequence) {
            byte[] iv = val.data.getOctetString();
            int tagLen = -1;
            if (val.data.available() != 0) {
                tagLen = val.data.getInteger();
                if (tagLen != SM4_GCM_TAG_LEN) {
                    throw new IOException(
                            "GCM parameter parsing error: unsupported tag len: " +
                            tagLen);
                }
                if (val.data.available() != 0) {
                    throw new IOException(
                            "GCM parameter parsing error: extra data");
                }
            }
            this.iv = iv;
            this.tagLen = tagLen;
        } else {
            throw new IOException("GCM parameter parsing error: no SEQ tag");
        }
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        return tagLen == -1 ? encode() : gcmEncode();
    }

    private byte[] encode() throws IOException {
        DerOutputStream out = new DerOutputStream();
        out.putOctetString(iv);
        return out.toByteArray();
    }

    private byte[] gcmEncode() throws IOException {
        DerOutputStream out = new DerOutputStream();
        DerOutputStream bytes = new DerOutputStream();

        bytes.putOctetString(iv);
        // Only put value 16.
        bytes.putInteger(SM4_GCM_TAG_LEN);
        out.write(DerValue.tag_Sequence, bytes);
        return out.toByteArray();
    }

    @Override
    protected byte[] engineGetEncoded(String encodingMethod)
            throws IOException {
        return engineGetEncoded();
    }

    @Override
    protected String engineToString() {
        String LINE_SEP = System.lineSeparator();

        String ivString = LINE_SEP + "    iv:" + LINE_SEP + "[";
        HexDumpEncoder encoder = new HexDumpEncoder();
        ivString += encoder.encodeBuffer(iv);
        ivString += "]" + LINE_SEP;
        return ivString;
    }
}
