package com.dirextalk.android;

import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

/**
 * Small fixed probe used only by the disposable Android acceptance harness.
 * HttpsURLConnection supplies the platform default TrustManager; no custom
 * trust store, permissive hostname verifier, or insecure TLS flag is allowed.
 */
public final class PlatformTrustProbe {
    private PlatformTrustProbe() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("one HTTPS endpoint is required");
        }
        HttpsURLConnection connection = (HttpsURLConnection) new URL(args[0]).openConnection();
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        connection.connect();
        connection.getResponseCode();
        connection.getServerCertificates();
        System.out.println("TRUSTED");
        connection.disconnect();
    }
}
