package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.crypto.util.Constants;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class SM4ParameterGenerator extends AlgorithmParameterGeneratorSpi {

    private SM4GenParameterSpec paramSpec;
    private SecureRandom random;

    @Override
    protected void engineInit(int keySize, SecureRandom random) {
        throw new InvalidParameterException(
                "Use init(AlgorithmParameterSpec paramSpec) " +
                        "or init(AlgorithmParameterSpec, SecureRandom)");
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec,
                              SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(paramSpec instanceof SM4GenParameterSpec)) {
            throw new InvalidAlgorithmParameterException(
                    "Only SM4GenParameterSpec is supported");
        }

        this.paramSpec = (SM4GenParameterSpec) paramSpec;
        this.random = random;
    }

    @Override
    protected AlgorithmParameters engineGenerateParameters() {
        if (random == null) {
            random = new SecureRandom();
        }

        return paramSpec.getParamSpecClass().equals(IvParameterSpec.class)
                ? genParams() : genGcmParams();
    }

    private AlgorithmParameters genParams() {
        byte[] iv = new byte[Constants.SM4_IV_LEN];
        random.nextBytes(iv);

        try {
            AlgorithmParameters params = CryptoInsts.getAlgorithmParameters("SM4");
            params.init(new IvParameterSpec(iv));
            return params;
        } catch (Exception ex) {
            throw new ProviderException("Unexpected exception", ex);
        }
    }

    private AlgorithmParameters genGcmParams() {
        byte[] iv = new byte[Constants.SM4_GCM_IV_LEN];
        random.nextBytes(iv);

        try {
            AlgorithmParameters params = CryptoInsts.getAlgorithmParameters("SM4");
            params.init(new GCMParameterSpec(Constants.SM4_GCM_TAG_LEN << 3, iv));
            return params;
        } catch (Exception ex) {
            throw new ProviderException("Unexpected exception", ex);
        }
    }
}
