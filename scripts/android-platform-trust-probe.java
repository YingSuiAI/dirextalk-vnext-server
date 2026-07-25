package com.dirextalk.android;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.HttpsURLConnection;

/**
 * Small fixed probe used only by the disposable Android acceptance harness.
 * HttpsURLConnection supplies the platform default TrustManager; no custom
 * trust store, permissive hostname verifier, or insecure TLS flag is allowed.
 */
public final class PlatformTrustProbe {
    private PlatformTrustProbe() {}

    private static boolean isCertificateRejection(Throwable error) {
        boolean handshake = false;
        for (Throwable current = error; current != null; current = current.getCause()) {
            if (current instanceof SSLHandshakeException) {
                handshake = true;
            }
            if (current instanceof CertPathValidatorException || current instanceof CertificateException) {
                return handshake;
            }
        }
        return false;
    }

    private static void writeResult(String path, String nonce, String result) throws IOException {
        File target = new File(path);
        File temporary = new File(path + ".tmp-" + nonce);
        byte[] bytes = (result + " " + nonce + "\n").getBytes(Charset.forName("UTF-8"));
        FileOutputStream output = new FileOutputStream(temporary, false);
        try {
            output.write(bytes);
            output.flush();
        } finally {
            output.close();
        }
        if (!temporary.renameTo(target)) {
            temporary.delete();
            throw new IOException("unable to publish probe result");
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3 || args[0].indexOf("https://") != 0 || !args[1].matches("[0-9a-f]{32}")) {
            throw new IllegalArgumentException("HTTPS endpoint, nonce, and result path are required");
        }
        String endpoint = args[0];
        String nonce = args[1];
        String resultPath = args[2];
        HttpsURLConnection connection = null;
        try {
            connection = (HttpsURLConnection) new URL(endpoint).openConnection();
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            connection.connect();
            if (connection.getResponseCode() != 200) {
                throw new IOException("unexpected HTTPS response");
            }
            connection.getServerCertificates();
            writeResult(resultPath, nonce, "TRUSTED");
        } catch (Throwable error) {
            if (isCertificateRejection(error)) {
                writeResult(resultPath, nonce, "UNTRUSTED");
                return;
            }
            try {
                writeResult(resultPath, nonce, "ERROR");
            } catch (IOException ignored) {
                // The host treats a missing result as a terminal probe failure.
            }
            System.exit(2);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
}
