package com.tencent.kona.java.nio;

import java.lang.reflect.Field;
import java.nio.Buffer;
import java.nio.ByteBuffer;

public class DirectBufferUtil {

    private static Field addressField;

    public static long address(ByteBuffer bb) {
        try {
            return getAddressField().getLong(bb);
        } catch (IllegalAccessException e) {
            throw new RuntimeException("Cannot get address", e);
        }
    }

    private static Field getAddressField() {
        if (addressField == null) {
            try {
                addressField = Buffer.class.getDeclaredField("address");
                addressField.setAccessible(true);
            } catch (NoSuchFieldException e) {
                throw new RuntimeException("Cannot get address field", e);
            }
        }

        return addressField;
    }
}
