/*
 * Copyright (c) 2009, 2024, Oracle and/or its affiliates. All rights reserved.
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

package com.tencent.kona.crypto.provider.nativeImpl;

import com.tencent.kona.crypto.util.Constants;
import com.tencent.kona.crypto.util.Sweeper;
import com.tencent.kona.sun.security.ec.ECPrivateKeyImpl;
import com.tencent.kona.sun.security.ec.ECPublicKeyImpl;
import com.tencent.kona.sun.security.jca.JCAUtil;
import com.tencent.kona.sun.security.util.ECUtil;
import com.tencent.kona.sun.security.util.SecurityProviderConstants;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.*;

import static com.tencent.kona.crypto.util.Constants.*;

/**
 * EC keypair generator.
 * Standard algorithm, minimum key length is 112 bits, maximum is 571 bits.
 *
 * @since 1.7
 */
public final class KonaECKeyPairGenerator extends KeyPairGeneratorSpi {

    private static final int KEY_SIZE_MIN = 112; // min bits (see ecc_impl.h)
    private static final int KEY_SIZE_MAX = 571; // max bits (see ecc_impl.h)

    // used to seed the keypair generator
    private SecureRandom random;

    // size of the key to generate, KEY_SIZE_MIN <= keySize <= KEY_SIZE_MAX
    private int keySize;

    // parameters specified via init, if any
    private AlgorithmParameterSpec params = null;

    private static final Sweeper SWEEPER = Sweeper.instance();
    private NativeECKeyPairGen keyPairGen = null;

    /**
     * Constructs a new ECKeyPairGenerator.
     */
    public KonaECKeyPairGenerator() {
        // initialize to default in case the app does not call initialize()
        initialize(SecurityProviderConstants.DEF_EC_KEY_SIZE, null);
    }

    // initialize the generator. See JCA doc
    @Override
    public void initialize(int keySize, SecureRandom random) {
        keyPairGen = null;

        checkKeySize(keySize);
        this.params = ECUtil.getECParameterSpec(keySize);
        if (params == null) {
            throw new InvalidParameterException(
                    "No EC parameters available for key size " + keySize + " bits");
        }
        this.random = random;

        byte[] encodedParams = ECUtil.encodeECParameterSpec((ECParameterSpec) params);
        int curveNID = Constants.getNID(encodedParams);
        keyPairGen = new NativeECKeyPairGen(curveNID);
        SWEEPER.register(this, new SweepNativeRef(keyPairGen));
    }

    // second initialize method. See JCA doc
    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        keyPairGen = null;

        ECParameterSpec ecSpec = null;

        if (params instanceof ECParameterSpec) {
            ECParameterSpec ecParams = (ECParameterSpec) params;
            ecSpec = ECUtil.getECParameterSpec(ecParams);
            if (ecSpec == null) {
                throw new InvalidAlgorithmParameterException(
                        "Curve not supported: " + params);
            }
        } else if (params instanceof ECGenParameterSpec) {
            String name = ((ECGenParameterSpec) params).getName();
            ecSpec = ECUtil.getECParameterSpec(name);
            if (ecSpec == null) {
                throw new InvalidAlgorithmParameterException(
                        "Unknown curve name: " + name);
            }
        } else {
            throw new InvalidAlgorithmParameterException(
                    "ECParameterSpec or ECGenParameterSpec required for EC");
        }

        // Not all known curves are supported by the native implementation
        byte[] encodedParams = ECUtil.encodeECParameterSpec(ecSpec);
        int curveNID = ensureCurveIsSupported(encodedParams, ecSpec);

        keyPairGen = new NativeECKeyPairGen(curveNID);
        SWEEPER.register(this, new SweepNativeRef(keyPairGen));
        this.params = ecSpec;

        this.keySize = ecSpec.getCurve().getField().getFieldSize();
        this.random = random;
    }

    private static int ensureCurveIsSupported(
            byte[] encodedParams, ECParameterSpec ecSpec)
            throws InvalidAlgorithmParameterException {

        int curveNID = Constants.getNID(encodedParams);
        if (curveNID == -1) {
            throw new InvalidAlgorithmParameterException(
                    "Curve not supported: " + ecSpec.toString());
        }

        // Check if ecSpec is a valid curve
        AlgorithmParameters ecParams = ECUtil.getECParameters();
        try {
            ecParams.init(ecSpec);
        } catch (InvalidParameterSpecException ex) {
            throw new InvalidAlgorithmParameterException(
                    "Curve not supported: " + ecSpec.toString());
        }

        return curveNID;
    }

    // generate the keypair. See JCA doc
    @Override
    public KeyPair generateKeyPair() {

        if (random == null) {
            random = JCAUtil.getSecureRandom();
        }

        try {
            Optional<KeyPair> kp = generateKeyPairImpl(random);
            if (kp.isPresent()) {
                return kp.get();
            }
        } catch (Exception ex) {
            throw new ProviderException(ex);
        }
        throw new ProviderException("Curve not supported: " +
                params.toString());
    }

    private Optional<KeyPair> generateKeyPairImpl(SecureRandom random)
            throws Exception {
        Object[] keyBytes = keyPairGen.genKeyPair();

        ECParameterSpec ecParams = (ECParameterSpec) params;

        BigInteger s = new BigInteger(1, (byte[]) keyBytes[0]);
        PrivateKey privateKey = new ECPrivateKeyImpl(s, ecParams);

        byte[] pubKey = (byte[]) keyBytes[1];
        ECPoint w = ECUtil.decodePoint(pubKey, ecParams.getCurve());
        PublicKey publicKey = new ECPublicKeyImpl(w, ecParams);

        return Optional.of(new KeyPair(publicKey, privateKey));
    }

    private void checkKeySize(int keySize) throws InvalidParameterException {
        if (keySize < KEY_SIZE_MIN) {
            throw new InvalidParameterException
                    ("Key size must be at least " + KEY_SIZE_MIN + " bits");
        }
        if (keySize > KEY_SIZE_MAX) {
            throw new InvalidParameterException
                    ("Key size must be at most " + KEY_SIZE_MAX + " bits");
        }
        this.keySize = keySize;
    }
}
