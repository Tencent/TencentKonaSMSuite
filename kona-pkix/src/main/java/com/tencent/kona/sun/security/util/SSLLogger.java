/*
 * Copyright (c) 2018, 2023, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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

package com.tencent.kona.sun.security.util;

import com.tencent.kona.sun.security.action.GetPropertyAction;
import com.tencent.kona.sun.security.util.Debug;
import com.tencent.kona.sun.security.x509.CertificateExtensions;
import com.tencent.kona.sun.security.x509.X509CertImpl;
import com.tencent.kona.sun.security.x509.X509CertInfo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Implementation of SSL logger.
 *
 * If the system property "com.tencent.kona.ssl.debug" is not defined, the debug logging
 * is turned off.  If the system property "com.tencent.kona.ssl.debug" is defined as
 * empty, the debug logger is specified by System.getLogger("com.tencent.kona.ssl"),
 * and applications can customize and configure the logger or use external
 * logging mechanisms.  If the system property "com.tencent.kona.ssl.debug" is defined
 * and non-empty, a private debug logger implemented in this class is used.
 */
public class SSLLogger {
    private static final Logger logger;
    private static final String property;
    public static final boolean isOn;

    static {
        String p = GetPropertyAction.privilegedGetProperty(
                "com.tencent.kona.ssl.debug");
        if (p != null) {
            if (p.isEmpty()) {
                property = "";
                logger = Logger.getLogger("com.tencent.kona.ssl");
            } else {
                property = p.toLowerCase(Locale.ENGLISH);
                if (property.equals("help")) {
                    help();
                }

                logger = new SSLConsoleLogger("com.tencent.kona.ssl", p);
            }
            isOn = true;
        } else {
            property = null;
            logger = null;
            isOn = false;
        }
    }

    private static void help() {
        System.err.println();
        System.err.println("help           print the help messages");
        System.err.println("expand         expand debugging information");
        System.err.println();
        System.err.println("all            turn on all debugging");
        System.err.println("ssl            turn on ssl debugging");
        System.err.println();
        System.err.println("The following can be used with ssl:");
        System.err.println("\trecord       enable per-record tracing");
        System.err.println("\thandshake    print each handshake message");
        System.err.println("\tkeygen       print key generation data");
        System.err.println("\tsession      print session activity");
        System.err.println("\tdefaultctx   print default SSL initialization");
        System.err.println("\tsslctx       print SSLContext tracing");
        System.err.println("\tsessioncache print session cache tracing");
        System.err.println("\tkeymanager   print key manager tracing");
        System.err.println("\ttrustmanager print trust manager tracing");
        System.err.println("\tpluggability print pluggability tracing");
        System.err.println();
        System.err.println("\thandshake debugging can be widened with:");
        System.err.println("\tdata         hex dump of each handshake message");
        System.err.println("\tverbose      verbose handshake message printing");
        System.err.println();
        System.err.println("\trecord debugging can be widened with:");
        System.err.println("\tplaintext    hex dump of record plaintext");
        System.err.println("\tpacket       print raw SSL/TLS packets");
        System.err.println();
        System.exit(0);
    }

    /**
     * Return true if the "com.tencent.kona.ssl.debug" property contains the
     * debug check points, or System.Logger is used.
     */
    public static boolean isOn(String checkPoints) {
        if (property == null) {              // debugging is turned off
            return false;
        } else if (property.isEmpty()) {     // use System.Logger
            return true;
        }                                   // use provider logger

        String[] options = checkPoints.split(",");
        for (String option : options) {
            option = option.trim();
            if (!SSLLogger.hasOption(option)) {
                return false;
            }
        }

        return true;
    }

    private static boolean hasOption(String option) {
        option = option.toLowerCase(Locale.ENGLISH);
        if (property.contains("all")) {
            return true;
        } else {
            // remove first occurrence of "sslctx" sinceAdd commentMore actions
            // it interferes with search for "ssl"
            String modified = property.replaceFirst("sslctx", "");
            if (modified.contains("ssl")) {
                // don't enable data and plaintext options by default
                if (!(option.equals("data")
                        || option.equals("packet")
                        || option.equals("plaintext"))) {
                    return true;
                }
            }
        }

        return property.contains(option);
    }

    public static void severe(String msg, Object... params) {
        SSLLogger.log(Level.SEVERE, msg, params);
    }

    public static void warning(String msg, Object... params) {
        SSLLogger.log(Level.WARNING, msg, params);
    }

    public static void info(String msg, Object... params) {
        SSLLogger.log(Level.INFO, msg, params);
    }

    public static void fine(String msg, Object... params) {
        SSLLogger.log(Level.FINE, msg, params);
    }

    public static void finer(String msg, Object... params) {
        SSLLogger.log(Level.FINER, msg, params);
    }

    public static void finest(String msg, Object... params) {
        SSLLogger.log(Level.ALL, msg, params);
    }

    private static void log(Level level, String msg, Object... params) {
        if (logger != null && logger.isLoggable(level)) {
            if (params == null || params.length == 0) {
                logger.log(level, msg);
            } else {
                try {
                    String formatted =
                            SSLSimpleFormatter.formatParameters(params);
                    logger.log(level, msg, formatted);
                } catch (Exception exp) {
                    // ignore it, just for debugging.
                }
            }
        }
    }

    public static String toString(Object... params) {
        try {
            return SSLSimpleFormatter.formatParameters(params);
        } catch (Exception exp) {
            return "unexpected exception thrown: " + exp.getMessage();
        }
    }

    // Logs a warning message and always returns false. This method
    // can be used as an OR Predicate to add a log in a stream filter.
    public static boolean logWarning(String option, String s) {
        if (SSLLogger.isOn && SSLLogger.isOn(option)) {
            SSLLogger.warning(s);
        }
        return false;
    }

    private static class SSLConsoleLogger extends Logger {
        private final String loggerName;
        private final boolean useCompactFormat;

        SSLConsoleLogger(String loggerName, String options) {
            super(loggerName, null);
            this.loggerName = loggerName;
            options = options.toLowerCase(Locale.ENGLISH);
            this.useCompactFormat = !options.contains("expand");
        }

        public String getName() {
            return loggerName;
        }

        public boolean isLoggable(Level level) {
            return level != Level.OFF;
        }

        @Override
        public void log(LogRecord record) {
            if (isLoggable(record.getLevel())) {
                try {
                    String formatted = null;
                    if (record.getThrown() != null) {
                        formatted =
                                SSLSimpleFormatter.format(this, record.getLevel(),
                                        record.getMessage(),
                                        record.getThrown());
                    } else {
                        formatted =
                                SSLSimpleFormatter.format(this, record.getLevel(),
                                        record.getMessage(),
                                        record.getParameters());
                    }
                    System.err.write(formatted.getBytes("UTF-8"));
                } catch (Exception exp) {
                    // ignore it, just for debugging.
                }
            }
        };
    }

    private static class SSLSimpleFormatter {
        private static final ThreadLocal<SimpleDateFormat> dateFormat =
                new ThreadLocal<SimpleDateFormat>() {
                    @Override protected SimpleDateFormat initialValue() {
                        return new SimpleDateFormat(
                                "yyyy-MM-dd kk:mm:ss.SSS z", Locale.ENGLISH);
                    }
                };

        private static final MessageFormat basicCertFormat = new MessageFormat(
                "\"version\"            : \"v{0}\",\n" +
                        "\"serial number\"      : \"{1}\",\n" +
                        "\"signature algorithm\": \"{2}\",\n" +
                        "\"issuer\"             : \"{3}\",\n" +
                        "\"not before\"         : \"{4}\",\n" +
                        "\"not  after\"         : \"{5}\",\n" +
                        "\"subject\"            : \"{6}\",\n" +
                        "\"subject public key\" : \"{7}\"\n",
                Locale.ENGLISH);

        private static final MessageFormat extendedCertFormart =
                new MessageFormat(
                        "\"version\"            : \"v{0}\",\n" +
                                "\"serial number\"      : \"{1}\",\n" +
                                "\"signature algorithm\": \"{2}\",\n" +
                                "\"issuer\"             : \"{3}\",\n" +
                                "\"not before\"         : \"{4}\",\n" +
                                "\"not  after\"         : \"{5}\",\n" +
                                "\"subject\"            : \"{6}\",\n" +
                                "\"subject public key\" : \"{7}\",\n" +
                                "\"extensions\"         : [\n" +
                                "{8}\n" +
                                "]\n",
                        Locale.ENGLISH);

        //
        // private static MessageFormat certExtFormat = new MessageFormat(
        //         "{0} [{1}] '{'\n" +
        //         "  critical: {2}\n" +
        //         "  value: {3}\n" +
        //         "'}'",
        //         Locale.ENGLISH);
        //

        private static final MessageFormat messageFormatNoParas =
                new MessageFormat(
                        "'{'\n" +
                                "  \"logger\"      : \"{0}\",\n" +
                                "  \"level\"       : \"{1}\",\n" +
                                "  \"thread id\"   : \"{2}\",\n" +
                                "  \"thread name\" : \"{3}\",\n" +
                                "  \"time\"        : \"{4}\",\n" +
                                "  \"caller\"      : \"{5}\",\n" +
                                "  \"message\"     : \"{6}\"\n" +
                                "'}'\n",
                        Locale.ENGLISH);

        private static final MessageFormat messageCompactFormatNoParas =
                new MessageFormat(
                        "{0}|{1}|{2}|{3}|{4}|{5}|{6}\n",
                        Locale.ENGLISH);

        private static final MessageFormat messageFormatWithParas =
                new MessageFormat(
                        "'{'\n" +
                                "  \"logger\"      : \"{0}\",\n" +
                                "  \"level\"       : \"{1}\",\n" +
                                "  \"thread id\"   : \"{2}\",\n" +
                                "  \"thread name\" : \"{3}\",\n" +
                                "  \"time\"        : \"{4}\",\n" +
                                "  \"caller\"      : \"{5}\",\n" +
                                "  \"message\"     : \"{6}\",\n" +
                                "  \"specifics\"   : [\n" +
                                "{7}\n" +
                                "  ]\n" +
                                "'}'\n",
                        Locale.ENGLISH);

        private static final MessageFormat messageCompactFormatWithParas =
                new MessageFormat(
                        "{0}|{1}|{2}|{3}|{4}|{5}|{6} (\n" +
                                "{7}\n" +
                                ")\n",
                        Locale.ENGLISH);

        private static final MessageFormat keyObjectFormat = new MessageFormat(
                "\"{0}\" : '{'\n" +
                        "{1}" +
                        "'}'\n",
                Locale.ENGLISH);

        // INFO: [TH: 123450] 2011-08-20 23:12:32.3225 PDT
        //     log message
        //     log message
        //     ...
        private static String format(SSLConsoleLogger logger, Level level,
                                     String message, Object ... parameters) {

            if (parameters == null || parameters.length == 0) {
                Object[] messageFields = {
                        logger.loggerName,
                        level.getName(),
                        Utilities.toHexString(Thread.currentThread().getId()),
                        Thread.currentThread().getName(),
                        dateFormat.get().format(new Date(System.currentTimeMillis())),
                        formatCaller(),
                        message
                };

                if (logger.useCompactFormat) {
                    return messageCompactFormatNoParas.format(messageFields);
                } else {
                    return messageFormatNoParas.format(messageFields);
                }
            }

            Object[] messageFields = {
                    logger.loggerName,
                    level.getName(),
                    Utilities.toHexString(Thread.currentThread().getId()),
                    Thread.currentThread().getName(),
                    dateFormat.get().format(new Date(System.currentTimeMillis())),
                    formatCaller(),
                    message,
                    (logger.useCompactFormat ?
                            formatParameters(parameters) :
                            Utilities.indent(formatParameters(parameters)))
            };

            if (logger.useCompactFormat) {
                return messageCompactFormatWithParas.format(messageFields);
            } else {
                return messageFormatWithParas.format(messageFields);
            }
        }

        private static String formatCaller() {
            StackTraceElement[] stElements = Thread.currentThread().getStackTrace();
            for (int i=1; i<stElements.length; i++) {
                StackTraceElement ste = stElements[i];
                if (!ste.getClassName().startsWith(SSLLogger.class.getName()) &&
                        !ste.getClassName().startsWith(Logger.class.getName())) {
                    return ste.getFileName() + ":" + ste.getLineNumber();
                }
            }
            return "unknown caller";
        }

        private static String formatParameters(Object ... parameters) {
            StringBuilder builder = new StringBuilder(512);
            boolean isFirst = true;
            for (Object parameter : parameters) {
                if (isFirst) {
                    isFirst = false;
                } else {
                    builder.append(",\n");
                }

                if (parameter instanceof Throwable) {
                    builder.append(formatThrowable((Throwable)parameter));
                } else if (parameter instanceof Certificate) {
                    builder.append(formatCertificate((Certificate)parameter));
                } else if (parameter instanceof ByteArrayInputStream) {
                    builder.append(formatByteArrayInputStream(
                            (ByteArrayInputStream)parameter));
                } else if (parameter instanceof ByteBuffer) {
                    builder.append(formatByteBuffer((ByteBuffer)parameter));
                } else if (parameter instanceof byte[]) {
                    builder.append(formatByteArrayInputStream(
                            new ByteArrayInputStream((byte[])parameter)));
                } else if (parameter instanceof Map.Entry) {
                    @SuppressWarnings("unchecked")
                    Map.Entry<String, ?> mapParameter =
                            (Map.Entry<String, ?>)parameter;
                    builder.append(formatMapEntry(mapParameter));
                } else {
                    builder.append(formatObject(parameter));
                }
            }

            return builder.toString();
        }

        // "throwable": {
        //   ...
        // }
        private static String formatThrowable(Throwable throwable) {
            StringBuilder builder = new StringBuilder(512);
            ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
            try (PrintStream out = new PrintStream(bytesOut)) {
                throwable.printStackTrace(out);
                builder.append(Utilities.indent(bytesOut.toString()));
            }
            Object[] fields = {
                    "throwable",
                    builder.toString()
            };

            return keyObjectFormat.format(fields);
        }

        // "certificate": {
        //   ...
        // }
        private static String formatCertificate(Certificate certificate) {

            if (!(certificate instanceof X509Certificate)) {
                return Utilities.indent(certificate.toString());
            }

            StringBuilder builder = new StringBuilder(512);
            try {
                X509CertImpl x509 =
                        X509CertImpl.toImpl((X509Certificate)certificate);
                X509CertInfo certInfo = x509.getInfo();
                CertificateExtensions certExts = certInfo.getExtensions();
                if (certExts == null) {
                    Object[] certFields = {
                            x509.getVersion(),
                            Debug.toString(x509.getSerialNumber()),
                            x509.getSigAlgName(),
                            x509.getIssuerX500Principal().toString(),
                            dateFormat.get().format(x509.getNotBefore()),
                            dateFormat.get().format(x509.getNotAfter()),
                            x509.getSubjectX500Principal().toString(),
                            x509.getPublicKey().getAlgorithm()
                    };
                    builder.append(Utilities.indent(
                            basicCertFormat.format(certFields)));
                } else {
                    StringBuilder extBuilder = new StringBuilder(512);
                    boolean isFirst = true;
                    for (Extension certExt : certExts.getAllExtensions()) {
                        if (isFirst) {
                            isFirst = false;
                        } else {
                            extBuilder.append(",\n");
                        }
                        extBuilder.append("{\n" +
                                Utilities.indent(certExt.toString()) + "\n}");
                    }
                    Object[] certFields = {
                            x509.getVersion(),
                            Debug.toString(x509.getSerialNumber()),
                            x509.getSigAlgName(),
                            x509.getIssuerX500Principal().toString(),
                            dateFormat.get().format(x509.getNotBefore()),
                            dateFormat.get().format(x509.getNotAfter()),
                            x509.getSubjectX500Principal().toString(),
                            x509.getPublicKey().getAlgorithm(),
                            Utilities.indent(extBuilder.toString())
                    };
                    builder.append(Utilities.indent(
                            extendedCertFormart.format(certFields)));
                }
            } catch (Exception ce) {
                // ignore the exception
            }

            Object[] fields = {
                    "certificate",
                    builder.toString()
            };

            return Utilities.indent(keyObjectFormat.format(fields));
        }

        private static String formatByteArrayInputStream(
                ByteArrayInputStream bytes) {
            StringBuilder builder = new StringBuilder(512);

            try (ByteArrayOutputStream bytesOut = new ByteArrayOutputStream()) {
                HexDumpEncoder hexEncoder = new HexDumpEncoder();
                hexEncoder.encodeBuffer(bytes, bytesOut);

                builder.append(Utilities.indent(bytesOut.toString()));
            } catch (IOException ioe) {
                // ignore it, just for debugging.
            }

            return builder.toString();
        }

        private static String formatByteBuffer(ByteBuffer byteBuffer) {
            StringBuilder builder = new StringBuilder(512);
            try (ByteArrayOutputStream bytesOut = new ByteArrayOutputStream()) {
                HexDumpEncoder hexEncoder = new HexDumpEncoder();
                hexEncoder.encodeBuffer(byteBuffer.duplicate(), bytesOut);
                builder.append(Utilities.indent(bytesOut.toString()));
            } catch (IOException ioe) {
                // ignore it, just for debugging.
            }

            return builder.toString();
        }

        private static String formatMapEntry(Map.Entry<String, ?> entry) {
            String key = entry.getKey();
            Object value = entry.getValue();

            String formatted;
            if (value instanceof String) {
                // "key": "value"
                formatted = "\"" + key + "\": \"" + value + "\"";
            } else if (value instanceof String[]) {
                // "key": [ "string a",
                //          "string b",
                //          "string c"
                //        ]
                StringBuilder builder = new StringBuilder(512);
                String[] strings = (String[])value;
                builder.append("\"" + key + "\": [\n");
                int len = strings.length;
                for (int i = 0; i < len; i++) {
                    String string = strings[i];
                    builder.append("      \"" + string + "\"");
                    if (i != len - 1) {
                        builder.append(",");
                    }
                    builder.append("\n");
                }
                builder.append("      ]");

                formatted = builder.toString();
            } else if (value instanceof byte[]) {
                formatted = "\"" + key + "\": \"" +
                        Utilities.toHexString((byte[])value) + "\"";
            } else if (value instanceof Byte) {
                formatted = "\"" + key + "\": \"" +
                        Utilities.toHexString((byte)value) + "\"";
            } else {
                formatted = "\"" + key + "\": " +
                        "\"" + value.toString() + "\"";
            }

            return Utilities.indent(formatted);
        }

        private static String formatObject(Object obj) {
            return obj.toString();
        }
    }
}
