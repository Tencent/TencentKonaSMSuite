package com.tencent.kona.crypto.provider;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidParameterException;
import java.security.spec.AlgorithmParameterSpec;

public class SM4GenParameterSpec implements AlgorithmParameterSpec {

    private final Class<? extends AlgorithmParameterSpec> paramSpecClass;

    public SM4GenParameterSpec(
            Class<? extends AlgorithmParameterSpec> paramSpecClass) {
        if (paramSpecClass != IvParameterSpec.class
                && paramSpecClass != GCMParameterSpec.class) {
            throw new InvalidParameterException(
                    "Only IvParameterSpec and GCMParameterSpec are supported");
        }

        this.paramSpecClass = paramSpecClass;
    }

    public Class<? extends AlgorithmParameterSpec> getParamSpecClass() {
        return paramSpecClass;
    }
}
