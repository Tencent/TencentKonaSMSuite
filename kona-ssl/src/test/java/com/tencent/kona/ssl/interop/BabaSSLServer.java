package com.tencent.kona.ssl.interop;

import com.tencent.kona.ssl.TestUtils;

import java.io.IOException;
import java.util.Collections;

/*
 * The OpenSSL/BabaSSL server.
 */
public class BabaSSLServer extends AbstractServer {

    private final int port;
    private final String command;

    private Process process;

    public BabaSSLServer(Builder builder) throws IOException {
        CertTuple certTuple = builder.getCertTuple();
        FileCert caCert = (FileCert) certTuple.trustedCert();
        FileCert signEeCert = (FileCert) certTuple.signEndEntityCert();
        FileCert encEeCert = (FileCert) certTuple.encEndEntityCert();
        if (encEeCert == null) {
            encEeCert = signEeCert;
        }

        String serverName = builder.getServerName();
        String alpn = Utilities.join(builder.getAppProtocols());

        port = builder.getPort() == 0
                ? TestUtils.getFreePort()
                : builder.getPort();

        command = Utilities.join(" ",
                getProduct().getPath().toString(),
                "s_server",
                Utilities.DEBUG ? "-state -debug -trace" : "",
                "-enable_ntls", "-ntls",
                Utilities.joinOptValue("-CAfile",
                        caCert == null ? null : caCert.certPath()),
                "-sign_cert " + signEeCert.certPath(),
                "-sign_key " + signEeCert.keyPath(),
                "-enc_cert " + encEeCert.certPath(),
                "-enc_key " + encEeCert.keyPath(),
                builder.getClientAuth() == ClientAuth.REQUIRED ? "-Verify 2" : "",
                builder.isUseSessTicket() ? "" : "-no_ticket",
                Utilities.joinOptValue("-servername", serverName),
                Utilities.joinOptValue("-alpn", alpn),
                "-WWW",
                "-accept " + port);
    }

    public static class Builder extends AbstractServer.Builder {

        @Override
        public BabaSSLServer build() throws IOException {
            return new BabaSSLServer(this);
        }
    }

    @Override
    public Product getProduct() {
        return BabaSSL.DEFAULT;
    }

    @Override
    public int getPort() {
        System.out.println("Waiting for port...");
        if (!Utilities.waitFor(BabaSSLServer::isAlive, this)) {
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
