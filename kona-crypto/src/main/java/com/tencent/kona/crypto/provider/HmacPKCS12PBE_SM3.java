package com.tencent.kona.crypto.provider;

import com.tencent.kona.com.sun.crypto.provider.HmacPKCS12PBECore;

import java.security.NoSuchAlgorithmException;

public class HmacPKCS12PBE_SM3 extends HmacPKCS12PBECore {

    public HmacPKCS12PBE_SM3() throws NoSuchAlgorithmException {
        super("SM3", 64);
    }
}
