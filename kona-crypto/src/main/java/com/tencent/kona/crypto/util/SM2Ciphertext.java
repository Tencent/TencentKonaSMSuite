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

package com.tencent.kona.crypto.util;

import com.tencent.kona.sun.security.util.DerInputStream;
import com.tencent.kona.sun.security.util.DerOutputStream;
import com.tencent.kona.sun.security.util.DerValue;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Objects;

import static com.tencent.kona.crypto.util.Constants.*;
import static com.tencent.kona.crypto.CryptoUtils.*;

/**
 * SM2 ciphertext wrapper used to convert a ciphertext in one format,
 * say ASN.1 DER C1C3C2, to another encoding format, like raw C1C2C3.
 */
public class SM2Ciphertext {

    private static final byte UNCOMPRESSED = 0x04;

    // C1: uncompressed EC point: 0x04||X||Y
    // C2: ciphertext
    // C3: digest
    public enum Format {

        // Not encoded ciphertext
        NONE,

        // C1||C3||C2 with ASN.1 DER
        // This is recommended by the specification GB/T 32918.5-2017
        DER_C1C3C2,

        // C1||C3||C2
        RAW_C1C3C2,

        // C1||C2||C3 with ASN.1 DER
        DER_C1C2C3,

        // C1||C2||C3
        RAW_C1C2C3
    }

    public static class Builder {

        private Format format;
        private byte[] encodedCiphertext;

        private byte[] coordX;
        private byte[] coordY;
        private byte[] digest;
        private byte[] ciphertext;

        public Builder format(Format format) {
            this.format = format;
            return this;
        }

        public Builder encodedCiphertext(byte[] encodedCiphertext) {
            Objects.requireNonNull(encodedCiphertext);

            this.encodedCiphertext = encodedCiphertext;
            return this;
        }

        public Builder coordX(byte[] coordX) {
            byte[] adjustedCoordX = adjustCoord(coordX);
            checkCoordinate(adjustedCoordX);

            this.coordX = adjustedCoordX;
            return this;
        }

        public Builder coordY(byte[] coordY) {
            byte[] adjustedCoordY = adjustCoord(coordY);
            checkCoordinate(adjustedCoordY);

            this.coordY = adjustedCoordY;
            return this;
        }

        public Builder digest(byte[] digest) {
            if (digest.length != SM3_DIGEST_LEN) {
                throw new IllegalArgumentException(
                        "Illegal digest: " + toHex(digest));
            }

            this.digest = digest;
            return this;
        }

        public Builder ciphertext(byte[] ciphertext) {
            Objects.requireNonNull(ciphertext);

            this.ciphertext = ciphertext;
            return this;
        }

        private static void checkCoordinate(byte[] coordinate) {
            if (coordinate.length != 32
                    && !(coordinate.length == 33 && coordinate[0] == 0x00)) {
                throw new IllegalArgumentException(
                        "Illegal coordinate: " + toHex(coordinate));
            }
        }

        public SM2Ciphertext build() throws IOException {
            return new SM2Ciphertext(this);
        }

        private byte[] adjustCoord(byte[] coord) {
            if (coord.length >= 32) {
                return coord;
            }

            byte[] adjusted = new byte[32];
            System.arraycopy(coord, 0, adjusted, adjusted.length - coord.length, coord.length);
            return adjusted;
        }
    }

    private final byte[] coordX;
    private final byte[] coordY;
    private final byte[] digest;
    private final byte[] ciphertext;

    public SM2Ciphertext(Builder builder) throws IOException {
        if (builder.format == Format.DER_C1C3C2
                || builder.format == Format.DER_C1C2C3) {
            DerInputStream derIn = new DerInputStream(builder.encodedCiphertext);

            DerValue[] values = derIn.getSequence(2);
            if (values.length != 4 || derIn.available() != 0) {
                throw new IOException("Invalid encoding for SM2 ciphertext");
            }

            byte[] x = values[0].getDataBytes();
            builder.coordX(x);

            byte[] y = values[1].getDataBytes();
            builder.coordY(y);

            if (builder.format == Format.DER_C1C3C2) {
                builder.digest(values[2].getDataBytes());
                builder.ciphertext(values[3].getDataBytes());
            } if (builder.format == Format.DER_C1C2C3) {
                builder.ciphertext(values[2].getDataBytes());
                builder.digest(values[3].getDataBytes());
            }
        } else if (builder.format == Format.RAW_C1C3C2
                || builder.format == Format.RAW_C1C2C3) {
            byte[] encodedCiphertext = builder.encodedCiphertext;

            // The public point key must start with 0x04
            // indicating the format is uncompressed.
            if (encodedCiphertext[0] != 0x04) {
                throw new IOException("For RAW_C1C3C2 and RAW_C1C2C3 formats, "
                        + "the ciphertext must start with 04");
            }

            builder.coordX(copy(encodedCiphertext, 1, 32));
            builder.coordY(copy(encodedCiphertext, 1 + 32, 32));

            if (builder.format == Format.RAW_C1C3C2) {
                builder.digest(copy(encodedCiphertext, 1 + 32 + 32, 32));
                builder.ciphertext(copy(encodedCiphertext, 1 + 32 + 32 + 32,
                        encodedCiphertext.length - (1 + 32 + 32 + 32)));
            } if (builder.format == Format.RAW_C1C2C3) {
                builder.ciphertext(copy(encodedCiphertext, 1 + 32 + 32,
                        encodedCiphertext.length - (1 + 32 + 32 + 32)));
                builder.digest(copy(encodedCiphertext,
                        encodedCiphertext.length - 32, 32));
            }
        }

        this.coordX = builder.coordX;
        this.coordY = builder.coordY;
        this.digest = builder.digest;
        this.ciphertext = builder.ciphertext;
    }

    public static Builder builder() {
        return new Builder();
    }

    public byte[] rawC1C3C2() {
        byte[] rawC1C3C2 = new byte[1 + 32 + 32 + 32 + ciphertext.length];
        rawC1C3C2[0] = UNCOMPRESSED;
        System.arraycopy(coordX, coordX.length == 33 ? 1 : 0, rawC1C3C2, 1, 32);
        System.arraycopy(coordY, coordY.length == 33 ? 1 : 0, rawC1C3C2, 1 + 32, 32);
        System.arraycopy(digest, 0, rawC1C3C2, 1 + 32 + 32, digest.length);
        System.arraycopy(ciphertext, 0, rawC1C3C2,
                1 + 32 + 32 + digest.length, ciphertext.length);
        return rawC1C3C2;
    }

    public byte[] rawC1C2C3() {
        byte[] rawC1C2C3 = new byte[1 + 32 + 32 + 32 + ciphertext.length];
        rawC1C2C3[0] = UNCOMPRESSED;
        System.arraycopy(coordX, coordX.length == 33 ? 1 : 0, rawC1C2C3, 1, 32);
        System.arraycopy(coordY, coordY.length == 33 ? 1 : 0, rawC1C2C3, 1 + 32, 32);
        System.arraycopy(ciphertext, 0, rawC1C2C3,
                1 + 32 + 32, ciphertext.length);
        System.arraycopy(digest, 0, rawC1C2C3,
                1 + 32 + 32 + ciphertext.length, digest.length);
        return rawC1C2C3;
    }

    public byte[] derC1C3C2() throws IOException {
        DerValue[] values = new DerValue[4];
        values[0] = new DerValue(DerValue.tag_Integer, new BigInteger(1, coordX).toByteArray());
        values[1] = new DerValue(DerValue.tag_Integer, new BigInteger(1, coordY).toByteArray());
        values[2] = new DerValue(DerValue.tag_OctetString, digest);
        values[3] = new DerValue(DerValue.tag_OctetString, ciphertext);
        DerOutputStream derOut = new DerOutputStream();
        derOut.putSequence(values);
        return derOut.toByteArray();
    }

    public byte[] derC1C2C3() throws IOException {
        DerValue[] values = new DerValue[4];
        values[0] = new DerValue(DerValue.tag_Integer, new BigInteger(1, coordX).toByteArray());
        values[1] = new DerValue(DerValue.tag_Integer, new BigInteger(1, coordY).toByteArray());
        values[2] = new DerValue(DerValue.tag_OctetString, ciphertext);
        values[3] = new DerValue(DerValue.tag_OctetString, digest);
        DerOutputStream derOut = new DerOutputStream();
        derOut.putSequence(values);
        return derOut.toByteArray();
    }
}
