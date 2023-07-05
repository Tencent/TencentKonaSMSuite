package com.tencent.kona.pkix.tool;

import com.tencent.kona.crypto.KonaCryptoProvider;
import com.tencent.kona.pkix.KonaPKIXProvider;
import com.tencent.kona.sun.security.tools.keytool.Main;

import java.security.Security;

public class KeyTool {

    static {
        Security.addProvider(new KonaCryptoProvider());
        Security.addProvider(new KonaPKIXProvider());
    }

    public static void main(String... args) throws Exception {
        Main.main(args);
    }
}
