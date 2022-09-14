package com.tencent.kona.ssl.interop;

import java.io.IOException;
import java.util.Collections;

/*
 * The OpenSSL/BabaSSL client.
 */
public class BabaSSLClient extends AbstractClient {

    private final String command;

    public BabaSSLClient(Builder builder) {
        CertTuple certTuple = builder.getCertTuple();
        FileCert caCert = (FileCert) certTuple.trustedCert();
        FileCert signEeCert = (FileCert) certTuple.signEndEntityCert();
        FileCert encEeCert = (FileCert) certTuple.encEndEntityCert();
        if (encEeCert == null) {
            encEeCert = signEeCert;
        }

        String serverName = builder.getServerName();
        String alpn = Utilities.join(builder.getAppProtocols());
        String sessIn = builder.sessIn();
        String sessOut = builder.sessOut();

        command = Utilities.join(" ",
                "echo " + builder.getMessage(),
                // Wait for the server response, e.g. session ticket.
                "|", "sleep 1", "|",
                getProduct().getPath().toString(),
                "s_client",
                Utilities.DEBUG ? "-state -debug -trace" : "-quiet",
                "-enable_ntls", "-ntls",
                Utilities.joinOptValue("-CAfile",
                        caCert == null ? null : caCert.certPath()),
                "-sign_cert " + signEeCert.certPath(),
                "-sign_key " +  signEeCert.keyPath(),
                "-enc_cert " + encEeCert.certPath(),
                "-enc_key " +  encEeCert.keyPath(),
                Utilities.joinOptValue("-cipher",
                        BabaSSLUtils.cipherSuite(builder.getCipherSuite())),
                Utilities.joinOptValue("-servername", serverName),
                Utilities.joinOptValue("-alpn", alpn),
                builder.isUseSessTicket() ? "" : "-no_ticket",
                Utilities.joinOptValue("-sess_in", sessIn),
                Utilities.joinOptValue("-sess_out", sessOut),
                "-no_ign_eof");
    }

    public static class Builder extends AbstractClient.Builder {

        private String sessIn;
        private String sessOut;

        public String sessIn() {
            return sessIn;
        }

        public Builder sessIn(String sessIn) {
            this.sessIn = sessIn;
            return this;
        }

        public String sessOut() {
            return sessOut;
        }

        public Builder sessOut(String sessOut) {
            this.sessOut = sessOut;
            return this;
        }

        @Override
        public BabaSSLClient build() {
            return new BabaSSLClient(this);
        }
    }

    @Override
    public Product getProduct() {
        return BabaSSL.DEFAULT;
    }

    @Override
    public void connect(String host, int port) throws IOException {
        String server = host + ":" + port;
        Process process = ProcUtils.shellProc(
                String.join(" ", command, "-connect", server),
                getLogPath(),
                Collections.emptyMap());
        try {
            process.waitFor();
        } catch (InterruptedException e) {
            throw new RuntimeException("Client is interrupted!", e);
        }

        if (process.exitValue() != 0) {
            throw new SSLTestException("Client exited abnormally!");
        }
    }

    @Override
    public void close() throws IOException {
        printLog();
        deleteLog();
    }
}
