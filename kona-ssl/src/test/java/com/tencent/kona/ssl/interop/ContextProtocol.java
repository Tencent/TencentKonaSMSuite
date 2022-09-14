package com.tencent.kona.ssl.interop;

public enum ContextProtocol {

    TLS("TLS"),
    TLCP("TLCP"),
    TLCP11("TLCPv1.1");

    public final String name;

    private ContextProtocol(String name) {
        this.name = name;
    }

    public String toString() {
        return name;
    }

    public static ContextProtocol contextProtocol(String name) {
        for (ContextProtocol contextProtocol : values()) {
            if (contextProtocol.name.equals(name)) {
                return contextProtocol;
            }
        }

        return null;
    }
}
