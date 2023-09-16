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

package com.tencent.kona.ssl.interop;

import com.tencent.kona.ssl.TestUtils;

import java.io.IOException;
import java.util.Collections;

/*
 * The OpenSSL server.
 */
public class OpenSSLServer extends AbstractServer {

    private final int port;
    private final String command;

    private Process process;

    public OpenSSLServer(Builder builder) throws IOException {
        CertTuple certTuple = builder.getCertTuple();
        FileCert caCert = (FileCert) certTuple.trustedCert();
        FileCert eeCert = (FileCert) certTuple.endEntityCert();
        FileCert altEeCert = (FileCert) certTuple.altEndEntityCert();

        String cert2Path = null;
        String key2Path = null;
        if (altEeCert != null) {
            cert2Path = altEeCert.certPath();
            key2Path = altEeCert.keyPath();
        }

        String cipherOption
                = OpenSSLUtils.cipherOption(builder.getCipherSuites());
        String serverName = builder.getServerName();
        String alpn = Utilities.join(builder.getAppProtocols());
        String namedGroups = OpenSSLUtils.joinNamedGroups(
                builder.getNamedGroups());

        port = builder.getPort() == 0
               ? TestUtils.getFreePort()
               : builder.getPort();

        command = Utilities.join(" ",
                getProduct().getPath().toString(),
                "s_server",
                Utilities.DEBUG ? "-state -debug -trace" : "",
                Utilities.joinOptValue("-CAfile",
                        caCert == null ? null : caCert.certPath()),
                "-cert " + eeCert.certPath(),
                "-key " + eeCert.keyPath(),
                Utilities.joinOptValue("-cert2", cert2Path),
                Utilities.joinOptValue("-key2", key2Path),
                cipherOption,
                builder.getClientAuth() == ClientAuth.REQUIRED ? "-Verify 2" : "",
                builder.isUseSessTicket() ? "" : "-no_ticket",
                Utilities.joinOptValue("-servername", serverName),
                Utilities.joinOptValue("-alpn", alpn),
                Utilities.joinOptValue("-groups", namedGroups),
                "-WWW",
                "-accept " + port);
    }

    public static class Builder extends AbstractServer.Builder {

        @Override
        public OpenSSLServer build() throws IOException {
            return new OpenSSLServer(this);
        }
    }

    @Override
    public Product getProduct() {
        return OpenSSL.DEFAULT;
    }

    @Override
    public int getPort() {
        System.out.println("Waiting for port...");
        if (!Utilities.waitFor(OpenSSLServer::isAlive, this)) {
            throw new RuntimeException("Server doesn't start in time.");
        }

        return port;
    }

    @Override
    public boolean isAlive() {
        return process != null && process.isAlive();
    }

    @Override
    public void accept() throws IOException {
        process = ProcUtils.shellProc(command, getLogPath(), Collections.emptyMap());
        try {
            process.waitFor();
        } catch (InterruptedException e) {
            throw new RuntimeException("Server is interrupted!", e);
        }

        if (process.exitValue() != 0) {
            throw new SSLTestException("Server exited abnormally!");
        }
    }

    @Override
    public void close() throws IOException {
        printLog();
        deleteLog();

        if (isAlive()) {
            Utilities.destroyProcess(process);
        }
    }
}
