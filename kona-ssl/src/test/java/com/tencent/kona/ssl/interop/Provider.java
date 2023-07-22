package com.tencent.kona.ssl.interop;

public enum Provider {

    JDK("JDK"), KONA("Kona");

    public final String name;

    private Provider(String name) {
        this.name = name;
    }

    public static Provider provider(String name) {
        for (Provider provider : values()) {
            if (provider.name.equals(name)) {
                return provider;
            }
        }

        return null;
    }
}
