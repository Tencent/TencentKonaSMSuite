/*
 * Copyright (c) 2020, Oracle and/or its affiliates. All rights reserved.
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
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.tencent.kona.ssl.interop;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

/*
 * An abstract client.
 */
public abstract class AbstractClient extends AbstractPeer implements Client {

    @Override
    public Path getLogPath() {
        return Paths.get("client.log");
    }

    @Override
    protected void printLog() throws IOException {
        System.out.println("---------- Client log start ----------");
        super.printLog();
        System.out.println("---------- Client log end ----------");
    }

    public static abstract class Builder extends AbstractPeer.Builder {

        // Indicate if try to read response.
        private boolean readResponse = true;

        public boolean isReadResponse() {
            return readResponse;
        }

        public Builder setReadResponse(boolean readResponse) {
            this.readResponse = readResponse;
            return this;
        }

        public abstract AbstractClient build() throws Exception;
    }
}
