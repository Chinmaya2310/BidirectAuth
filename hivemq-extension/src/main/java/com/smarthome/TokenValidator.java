package com.smarthome;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;

public class TokenValidator {

    private static final Logger log = LoggerFactory.getLogger(TokenValidator.class);
    private final RSAPublicKey arrowheadPublicKey;
    private RSAPrivateKey brokerPrivateKey;

    public RSAPrivateKey getBrokerPrivateKey() {
        return brokerPrivateKey;
    }


    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public TokenValidator(RSAPublicKey arrowheadPublicKey) {
        this.arrowheadPublicKey = arrowheadPublicKey;
    }

    public void loadBrokerPrivateKey(String keystorePath, String password) {
        try {
            log.info("Loading broker private key from: {}", keystorePath);
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(keystorePath), password.toCharArray());
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                log.info("Found alias: {}", alias);
                if (ks.isKeyEntry(alias)) {
                    brokerPrivateKey = (RSAPrivateKey) ks.getKey(alias, password.toCharArray());
                    log.info("Broker private key loaded alias={}", alias);
                    break;
                }
            }
            if (brokerPrivateKey == null) {
                log.error("No private key found in keystore");
            }
        } catch (Exception e) {
            log.error("Failed to load broker private key: {}", e.getMessage(), e);
        }
    }

    public ValidationResult validateConnect(String tokenString, String systemName) {
        try {
            String jwt = resolveJWT(tokenString);
            if (jwt == null) return ValidationResult.fail("Cannot resolve JWT");
            DecodedJWT decoded = verifySignature(jwt);
            if (decoded == null) return ValidationResult.fail("Invalid JWT signature");
            String consumerName = getClaim(decoded, "cid");
            if (consumerName == null) {
                log.info("No cid claim - skipping consumer check");
                return ValidationResult.ok();
            }
            String baseName = consumerName.split("\\.")[0];
            if (!baseName.equals(systemName))
                return ValidationResult.fail("systemName mismatch: token=" + baseName + " client=" + systemName);
            return ValidationResult.ok();
        } catch (TokenExpiredException e) {
            return ValidationResult.fail("JWT expired");
        } catch (Exception e) {
            return ValidationResult.fail("Validation error: " + e.getMessage());
        }
    }

    public ValidationResult validatePacket(String tokenString, String systemName,
                                           String topic, String expectedAction) {
        try {
            String jwt = resolveJWT(tokenString);
            if (jwt == null) return ValidationResult.fail("Cannot resolve JWT");
            DecodedJWT decoded = verifySignature(jwt);
            if (decoded == null) return ValidationResult.fail("Invalid JWT signature");

            // ===== Milestone 4: enforce systemName + topic + action =====
            // 1. Verify the cid (consumer) in the token matches the requesting client.
            String consumerName = getClaim(decoded, "cid");
            if (consumerName == null) return ValidationResult.fail("Missing cid claim");
            String baseName = consumerName.split("\\.")[0];
            if (!baseName.equals(systemName))
                return ValidationResult.fail("systemName mismatch: token=" + baseName + " client=" + systemName);

            // 2. Verify the sid (service id) authorizes this topic + action.
            String sid = getClaim(decoded, "sid");
            if (sid == null) return ValidationResult.fail("Missing sid claim");
            ServicePerm perm = SERVICE_PERMS.get(sid);
            if (perm == null) return ValidationResult.fail("Unknown service id: " + sid);
            if (!perm.topic.equals(topic))
                return ValidationResult.fail("Topic mismatch: token-service=" + sid +
                    " (topic=" + perm.topic + ") packet-topic=" + topic);
            if (!perm.action.equals(expectedAction))
                return ValidationResult.fail("Action mismatch: token-service=" + sid +
                    " (action=" + perm.action + ") packet-action=" + expectedAction);

            return ValidationResult.ok();
        } catch (TokenExpiredException e) {
            return ValidationResult.fail("JWT expired");
        } catch (Exception e) {
            return ValidationResult.fail("Validation error: " + e.getMessage());
        }
    }

    public String peekConsumerName(String tokenString) {
        try {
            String jwt = resolveJWT(tokenString);
            if (jwt == null) return null;
            DecodedJWT decoded = JWT.decode(jwt);
            String name = getClaim(decoded, "cid");
            if (name != null) return name.split("\\.")[0];
        } catch (Exception ignored) {}
        return null;
    }

    private String resolveJWT(String tokenString) {
        if (tokenString == null) return null;
        String[] parts = tokenString.split("\\.");
        log.debug("Token has {} parts", parts.length);
        if (parts.length == 5) {
            log.info("Detected JWE token - decrypting with broker private key");
            return decryptJWE(tokenString);
        }
        if (parts.length == 3) {
            return tokenString;
        }
        return null;
    }

    private String decryptJWE(String jweToken) {
        if (brokerPrivateKey == null) {
            log.error("Broker private key not loaded - cannot decrypt JWE");
            return null;
        }
        try {
            String[] parts = jweToken.split("\\.");
            byte[] encryptedKey = Base64.getUrlDecoder().decode(parts[1]);
            byte[] iv = Base64.getUrlDecoder().decode(parts[2]);
            byte[] ciphertext = Base64.getUrlDecoder().decode(parts[3]);

            // Decrypt content encryption key with RSA-OAEP-256
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC");
            rsaCipher.init(Cipher.DECRYPT_MODE, brokerPrivateKey);
            byte[] contentKey = rsaCipher.doFinal(encryptedKey);
            log.info("Content key decrypted length={}", contentKey.length);

            // A256CBC-HS512: first 32 bytes = HMAC key, last 32 bytes = AES key
            byte[] aesKey = Arrays.copyOfRange(contentKey, 32, 64);

            // Decrypt ciphertext with AES-256-CBC
            SecretKey secretKey = new SecretKeySpec(aesKey, "AES");
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] decrypted = aesCipher.doFinal(ciphertext);

            String innerJWT = new String(decrypted, StandardCharsets.UTF_8);
            log.info("JWE decrypted successfully inner JWT length={}", innerJWT.length());
            return innerJWT;

        } catch (Exception e) {
            log.error("JWE decryption failed: {}", e.getMessage(), e);
            return null;
        }
    }

    private DecodedJWT verifySignature(String jwt) {
        try {
            return JWT.require(Algorithm.RSA256(arrowheadPublicKey, null)).build().verify(jwt);
        } catch (Exception e) {
            try {
                return JWT.require(Algorithm.RSA512(arrowheadPublicKey, null)).build().verify(jwt);
            } catch (Exception e2) {
                log.warn("JWT verification failed: {}", e.getMessage());
                return null;
            }
        }
    }

    private String getClaim(DecodedJWT jwt, String claimName) {
        Claim claim = jwt.getClaim(claimName);
        if (!claim.isNull()) return claim.asString();
        return null;
    }

    // Milestone 4: maps Arrowhead service-id (sid) → permitted topic + action.
    // TODO: fetch from Service Registry on startup instead of hardcoding.
    private record ServicePerm(String topic, String action) {}
    private static final java.util.Map<String, ServicePerm> SERVICE_PERMS = java.util.Map.of(
        "temperature-reading",   new ServicePerm("room/temperature", "PUBLISH"),
        "temperature-subscribe", new ServicePerm("room/temperature", "SUBSCRIBE"),
        "service-1", new ServicePerm("room/service-1", "PUBLISH")
    );

    public record ValidationResult(boolean valid, String reason) {
        public static ValidationResult ok() { return new ValidationResult(true, null); }
        public static ValidationResult fail(String reason) { return new ValidationResult(false, reason); }
    }
}
