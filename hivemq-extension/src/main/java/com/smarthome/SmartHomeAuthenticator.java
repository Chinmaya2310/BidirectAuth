package com.smarthome;

import com.hivemq.extension.sdk.api.auth.SimpleAuthenticator;
import com.hivemq.extension.sdk.api.auth.parameter.SimpleAuthInput;
import com.hivemq.extension.sdk.api.auth.parameter.SimpleAuthOutput;
import com.hivemq.extension.sdk.api.packets.connect.ConnackReasonCode;
import com.hivemq.extension.sdk.api.packets.general.UserProperties;
import com.hivemq.extension.sdk.api.packets.general.UserProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.List;
import java.util.Optional;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

public class SmartHomeAuthenticator implements SimpleAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(SmartHomeAuthenticator.class);
    private final TokenValidator tokenValidator;
    private static final SecureRandom secureRandom = new SecureRandom();

    public SmartHomeAuthenticator(TokenValidator tokenValidator) {
        this.tokenValidator = tokenValidator;
    }

    @Override
    public void onConnect(SimpleAuthInput input, SimpleAuthOutput output) {

        String clientId = input.getClientInformation().getClientId();
        log.info("[CONNECT] Client: {}", clientId);

        // Step 1 - Read User Properties from CONNECT packet
        UserProperties props = input.getConnectPacket().getUserProperties();
        Optional<String> systemName = getProperty(props, "systemName");
        Optional<String> token = getProperty(props, "arrowheadToken");
        Optional<String> clientNonce = getProperty(props, "clientNonce");

        // Log clientNonce - replay protection added in a later milestone
        if (clientNonce.isPresent()) {
            log.info("[CONNECT] clientNonce: {}", clientNonce.get());
        } else {
            log.warn("[CONNECT] No clientNonce - old client?");
        }

        // ===== BidirectAuth Step 4 (sub-step 2b) =====
        // Generate brokerNonce + sign (clientNonce || brokerNonce) with broker.priv
        // Not yet sent to client — just verifying crypto pipeline works.
        if (clientNonce.isPresent()) {
            try {
                byte[] brokerNonceBytes = new byte[16];
                secureRandom.nextBytes(brokerNonceBytes);
                String brokerNonce = bytesToHex(brokerNonceBytes);
                log.info("[AUTH] brokerNonce generated: {}", brokerNonce);

                String concatenated = clientNonce.get() + brokerNonce;
                RSAPrivateKey brokerPriv = tokenValidator.getBrokerPrivateKey();
                if (brokerPriv == null) {
                    log.error("[AUTH] broker.priv not loaded - cannot sign brokerProof");
                } else {
                    Signature sig = Signature.getInstance("SHA256withRSA");
                    sig.initSign(brokerPriv);
                    sig.update(concatenated.getBytes(StandardCharsets.UTF_8));
                    byte[] signature = sig.sign();
                    String brokerProof = Base64.getEncoder().encodeToString(signature);
                    log.info("[AUTH] brokerProof signed: length={} bytes, b64 first 40 chars: {}",
                            signature.length, brokerProof.substring(0, Math.min(40, brokerProof.length())));
                }
            } catch (Exception e) {
                log.error("[AUTH] Failed to generate brokerProof: {}", e.getMessage(), e);
            }
        }

        // Step 2 - Check systemName exists
        if (systemName.isEmpty()) {
            log.warn("[CONNECT] REJECTED {} - missing systemName", clientId);
            output.failAuthentication(ConnackReasonCode.NOT_AUTHORIZED, "Missing systemName");
            return;
        }

        // Step 3 - Check token exists
        if (token.isEmpty()) {
            log.warn("[CONNECT] REJECTED {} - missing arrowheadToken", clientId);
            output.failAuthentication(ConnackReasonCode.NOT_AUTHORIZED, "Missing arrowheadToken");
            return;
        }

        // Step 4 - Validate the token
        TokenValidator.ValidationResult result =
            tokenValidator.validateConnect(token.get(), systemName.get());

        if (result.valid()) {
            log.info("[CONNECT] ACCEPTED client={} systemName={}", clientId, systemName.get());
            output.authenticateSuccessfully();
        } else {
            log.warn("[CONNECT] REJECTED client={} reason={}", clientId, result.reason());
            output.failAuthentication(ConnackReasonCode.NOT_AUTHORIZED, result.reason());
        }
    }

    // Helper to get a specific User Property by name
    private Optional<String> getProperty(UserProperties props, String name) {
        List<UserProperty> list = props.asList();
        return list.stream()
            .filter(p -> name.equals(p.getName()))
            .map(UserProperty::getValue)
            .findFirst();
    }

    // Convert bytes to lowercase hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
