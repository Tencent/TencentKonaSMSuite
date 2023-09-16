/*
 * Copyright (C) 2022, 2023, THL A29 Limited, a Tencent company. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package com.tencent.kona.ssl;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * The test for this provider.
 */
public class KonaSSLProviderTest {

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testAddProvider() {
        Assertions.assertNotNull(Security.getProvider(TestUtils.PROVIDER));
    }

    @Test
    public void testProtocols() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.3", TestUtils.PROVIDER);
        Assertions.assertEquals("TLSv1.3", context.getProtocol());

        context = SSLContext.getInstance("TLSv1.2", TestUtils.PROVIDER);
        Assertions.assertEquals("TLSv1.2", context.getProtocol());

        Assertions.assertThrows(NoSuchAlgorithmException.class,
                () -> SSLContext.getInstance("TLSv1.1", TestUtils.PROVIDER));

        Assertions.assertThrows(NoSuchAlgorithmException.class,
                () -> SSLContext.getInstance("TLSv1", TestUtils.PROVIDER));

        Assertions.assertThrows(NoSuchAlgorithmException.class,
                () -> SSLContext.getInstance("SSLv3", TestUtils.PROVIDER));
    }
}
