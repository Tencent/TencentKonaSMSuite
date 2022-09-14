package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.util.Constants;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

public class SM2PublicKeyParameters extends ECPublicKeyParameters {

    public SM2PublicKeyParameters(ECPoint point) {
        super(point, Constants.SM2_DOMAIN);
    }
}
