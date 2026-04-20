package com.smarthome;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyLoader {

    private static final Logger log = LoggerFactory.getLogger(KeyLoader.class);

    public RSAPublicKey loadPublicKeyFromArrowhead(
            String authUrl,
            String brokerKeystore,
            String keystorePassword,
            String truststore,
            String truststorePassword) throws Exception {

        log.info("Fetching RSA public key from Arrowhead: {}", authUrl);

        // Load broker keystore (HiveMQ client certificate)
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream(brokerKeystore), keystorePassword.toCharArray());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, keystorePassword.toCharArray());

        // Load truststore
        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(new FileInputStream(truststore), truststorePassword.toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        // Create SSL context with client certificate
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        // Make HTTPS call using standard Java HttpsURLConnection
        URL url = new URL(authUrl + "/authorization/publickey");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(sslContext.getSocketFactory());
        conn.setHostnameVerifier((hostname, session) -> true);
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        int responseCode = conn.getResponseCode();
        log.info("Arrowhead response code: {}", responseCode);

        InputStream is = conn.getInputStream();
        String body = new String(is.readAllBytes()).trim();
        body = body.replace("\"", "").trim();

        log.info("Public key received length={}", body.length());

        // Decode base64 to RSA public key
        byte[] keyBytes = Base64.getDecoder().decode(body);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKey key = (RSAPublicKey) kf.generatePublic(spec);

        log.info("RSA public key fetched from Arrowhead successfully");
        return key;
    }
}
