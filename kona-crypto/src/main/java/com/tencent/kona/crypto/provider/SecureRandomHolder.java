package com.tencent.kona.crypto.provider;

import java.security.SecureRandom;

final class SecureRandomHolder {

    private static final SecureRandom RANDOM = new SecureRandom();

    private SecureRandomHolder() {}

    static SecureRandom getRandom() {
        return SecureRandomHolder.RANDOM;
    }
}
