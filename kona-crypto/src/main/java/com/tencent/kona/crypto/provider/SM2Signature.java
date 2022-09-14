package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;
import org.bouncycastle.jcajce.provider.asymmetric.ec.GMSignatureSpi;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Objects;

import static com.tencent.kona.crypto.util.Constants.defaultId;

public class SM2Signature extends GMSignatureSpi.sm3WithSM2 {

    private static final String PARAM_ID = "id";
    private static final String PARAM_PUBLIC_KEY = "publicKey";

    private SM2PrivateKey privateKey;
    private SM2PublicKey publicKey;
    private byte[] id = null;

    @Override
    protected void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException {
        this.publicKey = null;

        if (!(publicKey instanceof ECPublicKey)) {
            throw new InvalidKeyException("Only ECPublicKey accepted!");
        }

        this.publicKey = new SM2PublicKey((ECPublicKey) publicKey);
        setParamId();
        super.engineInitVerify(publicKey);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey)
            throws InvalidKeyException {
        this.privateKey = null;

        if (!(privateKey instanceof ECPrivateKey)) {
            throw new InvalidKeyException("Only ECPrivateKey accepted!");
        }

        this.privateKey = new SM2PrivateKey((ECPrivateKey) privateKey);
        setParamId();
        super.engineInitSign(privateKey);
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        super.engineUpdate(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len)
            throws SignatureException {
        super.engineUpdate(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (privateKey == null) {
            throw new SignatureException("Private Key not initialized");
        }

        return super.engineSign();
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (publicKey == null) {
            throw new SignatureException("Public Key not initialized");
        }

        return super.engineVerify(sigBytes);
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof SM2SignatureParameterSpec)) {
            throw new InvalidAlgorithmParameterException(
                    "Only accept SM2SignatureParameterSpec");
        }

        SM2SignatureParameterSpec paramSpec = (SM2SignatureParameterSpec) params;
        publicKey = new SM2PublicKey(paramSpec.getPublicKey());
        id = paramSpec.getId();
    }

    @Override
    protected void engineSetParameter(String param, Object value)
            throws InvalidParameterException {
        Objects.requireNonNull(param);
        Objects.requireNonNull(value);

        if (isParamId(param)) {
            id = ((byte[]) value).clone();
        } else if (isParamPublicKey(param)) {
            SM2PublicKey key = new SM2PublicKey((ECPublicKey) value);
            byte[] encodedKey = key.getEncoded();

            if (encodedKey.length == 0) {
                throw new InvalidParameterException(
                        "Invalid public key of parameter");
            }

            if (publicKey != null) {
                if (!Arrays.equals(publicKey.getEncoded(), encodedKey)) {
                    throw new InvalidParameterException(
                            "public key of parameter is not match");
                }
            }
        } else {
            throw new InvalidParameterException("unsupported parameter: " + param);
        }
    }

    @Override
    protected Object engineGetParameter(String param)
            throws InvalidParameterException {
        if (isParamId(param)) {
            return id == null ? defaultId() : id.clone();
        } else if (isParamPublicKey(param)) {
            return publicKey;
        } else {
            throw new InvalidParameterException(
                    "Only support id and publicKey: " + param);
        }
    }

    private void setParamId() throws InvalidParameterException {
        if (id == null) {
            // Just use the default ID
            id = defaultId();
        }

        try {
            super.engineSetParameter(new SM2ParameterSpec(id));
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException("set id of parameter failed");
        }
    }

    private static boolean isParamId(String paramName) {
        return paramName.equalsIgnoreCase(PARAM_ID);
    }

    private static boolean isParamPublicKey(String paramName) {
        return paramName.equalsIgnoreCase(PARAM_PUBLIC_KEY);
    }
}
