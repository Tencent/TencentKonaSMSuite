package com.tencent.kona.ssl.interop;

import java.nio.file.Path;
import java.nio.file.Paths;

/*
 * OpenSSL product.
 */
public class OpenSSL extends AbstractProduct {

    public static final OpenSSL DEFAULT = new OpenSSL(
            "OpenSSL",
            System.getProperty("test.openssl.path", "babassl"));

    private final String name;
    private final Path path;

    public OpenSSL(String name, Path path) {
        this.name = name;
        this.path = path;
    }

    public OpenSSL(String name, String path) {
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
