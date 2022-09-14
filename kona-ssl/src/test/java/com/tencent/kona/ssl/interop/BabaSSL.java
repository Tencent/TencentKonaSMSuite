package com.tencent.kona.ssl.interop;

import java.nio.file.Path;
import java.nio.file.Paths;

/*
 * OpenSSL/BabaSSL product.
 * This product is used for testing TLCP/NTLS/GMTLS.
 */
public class BabaSSL extends AbstractProduct {

    public static final BabaSSL DEFAULT = new BabaSSL(
            "BabaSSL",
            System.getProperty("test.babassl.path", "babassl"));

    private final String name;
    private final Path path;

    public BabaSSL(String name, Path path) {
        this.name = name;
        this.path = path;
    }

    public BabaSSL(String name, String path) {
        this(name, Paths.get(path));
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Path getPath() {
        return path;
    }
}
