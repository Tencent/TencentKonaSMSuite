package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.util.Constants;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

import java.math.BigInteger;

public class SM2PrivateKeyParameters extends ECPrivateKeyParameters {

    public SM2PrivateKeyParameters(BigInteger d) {
        super(d, Constants.SM2_DOMAIN);
    }
}
