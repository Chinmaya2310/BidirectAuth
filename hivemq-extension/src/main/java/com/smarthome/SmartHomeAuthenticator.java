package com.smarthome;

import com.hivemq.extension.sdk.api.auth.EnhancedAuthenticator;
import com.hivemq.extension.sdk.api.auth.parameter.EnhancedAuthConnectInput;
import com.hivemq.extension.sdk.api.auth.parameter.EnhancedAuthInput;
import com.hivemq.extension.sdk.api.auth.parameter.EnhancedAuthOutput;
import com.hivemq.extension.sdk.api.packets.general.DisconnectedReasonCode;
import com.hivemq.extension.sdk.api.packets.general.UserProperties;
import com.hivemq.extension.sdk.api.packets.general.UserProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

public class SmartHomeAuthenticator implements EnhancedAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(SmartHomeAuthenticator.class);
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final String AUTH_METHOD = "ArrowheadBidirectAuth";

    private final TokenValidator tokenValidator;

    public SmartHomeAuthenticator(TokenValidator tokenValidator) {
        this.tokenValidator = tokenValidator;
    }

    @Override
    public void onConnect(EnhancedAuthConnectInput input, EnhancedAuthOutput output) {
        String clientId = input.getClientInformation().getClientId();
        log.info("[CONNECT] Client: {}", clientId);

        // Read User Properties
        UserProperties props = input.getConnectPacket().getUserProperties();
        Optional<String> systemName = getProperty(props, "systemName");
        Optional<String> token = getProperty(props, "arrowheadToken");
        Optional<String> clientNonce = getProperty(props, "clientNonce");

        if (clientNonce.isPresent()) {
            log.info("[CONNECT] clientNonce: {}", clientNonce.get());
        } else {
            log.warn("[CONNECT] No clientNonce - old client?");
        }

        // Validate basics
        if (systemName.isEmpty()) {
            log.warn("[CONNECT] REJECTED {} - missing systemName", clientId);
            output.failAuthentication(DisconnectedReasonCode.NOT_AUTHORIZED, "Missing systemName");
            return;
        }
        if (token.isEmpty()) {
            log.warn("[CONNECT] REJECTED {} - missing arrowheadToken", clientId);
            output.failAuthentication(DisconnectedReasonCode.NOT_AUTHORIZED, "Missing arrowheadToken");
            return;
        }

        // Validate token (Step 6 in the diagram)
        TokenValidator.ValidationResult result =
            tokenValidator.validateConnect(token.get(), systemName.get());
        if (!result.valid()) {
            log.warn("[CONNECT] REJECTED client={} reason={}", clientId, result.reason());
            output.failAuthentication(DisconnectedReasonCode.NOT_AUTHORIZED, result.reason());
            return;
        }
        log.info("[CONNECT] Token valid for client={}", clientId);

        // Decide whether this client wants enhanced auth (BidirectAuth)
        Optional<String> authMethod = input.getConnectPacket().getAuthenticationMethod();
        boolean useBidirect = authMethod.isPresent() && AUTH_METHOD.equals(authMethod.get());

        if (!useBidirect) {
            // Backwards-compatible path: client did not opt in to BidirectAuth
            log.info("[CONNECT] ACCEPTED (no BidirectAuth) client={}", clientId);
            output.authenticateSuccessfully();
            return;
        }

        // ===== BidirectAuth Step 4 =====
        // Client opted in. Generate brokerNonce, sign brokerProof, send via AUTH packet.
        if (clientNonce.isEmpty()) {
            log.warn("[CONNECT] REJECTED client={} - BidirectAuth requested but clientNonce missing",
                    clientId);
            output.failAuthentication(DisconnectedReasonCode.NOT_AUTHORIZED,
                    "BidirectAuth requires clientNonce");
            return;
        }
        try {
            byte[] brokerNonceBytes = new byte[16];
            secureRandom.nextBytes(brokerNonceBytes);
            String brokerNonce = bytesToHex(brokerNonceBytes);

            String concatenated = clientNonce.get() + brokerNonce;
            RSAPrivateKey brokerPriv = tokenValidator.getBrokerPrivateKey();
            if (brokerPriv == null) {
                log.error("[AUTH] broker.priv not loaded - cannot sign brokerProof");
                output.failAuthentication(DisconnectedReasonCode.SERVER_BUSY,
                        "Broker not ready for BidirectAuth");
                return;
            }

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(brokerPriv);
            sig.update(concatenated.getBytes(StandardCharsets.UTF_8));
            byte[] signature = sig.sign();
            String brokerProof = Base64.getEncoder().encodeToString(signature);

            log.info("[AUTH] brokerNonce: {}", brokerNonce);
            log.info("[AUTH] brokerProof: length={} bytes, b64 first 40: {}",
                    signature.length, brokerProof.substring(0, Math.min(40, brokerProof.length())));

            // Persist a marker on this connection — onAuth will check it.
            // ConnectionAttributeStore is per-connection state and doesn't need a clientId key.
            input.getConnectionInformation().getConnectionAttributeStore()
                .putAsString("bidirect-pending", "1");

            // Pack brokerNonce + brokerProof into Authentication Data field.
            // Format: "brokerNonce:brokerProof" (both ASCII-safe)
            String authPayload = brokerNonce + ":" + brokerProof;
            byte[] authData = authPayload.getBytes(StandardCharsets.UTF_8);

            log.info("[AUTH] Sending AUTH packet (Continue Authentication) to client={}", clientId);
            output.continueAuthentication(authData);

        } catch (Exception e) {
            log.error("[AUTH] Failed to generate brokerProof for client={}: {}",
                    clientId, e.getMessage(), e);
            output.failAuthentication(DisconnectedReasonCode.SERVER_BUSY,
                    "BidirectAuth signing failed");
        }
    }

    @Override
    public void onAuth(EnhancedAuthInput input, EnhancedAuthOutput output) {
        String clientId = input.getClientInformation().getClientId();
        String authMethod = input.getAuthPacket().getAuthenticationMethod();

        log.info("[AUTH] onAuth called for client={} method={}", clientId,
                authMethod == null ? "(none)" : authMethod);

        if (!AUTH_METHOD.equals(authMethod)) {
            log.warn("[AUTH] Wrong authentication method - rejecting client={}", clientId);
            output.failAuthentication(DisconnectedReasonCode.NOT_AUTHORIZED,
                    "Unsupported auth method");
            return;
        }

        // 2c-2: Client just acknowledges. We don't validate any data here yet.
        // 2c-3 (and beyond) may add: client signs (brokerNonce || ?) to prove it received,
        // but the bidirectional cryptographic proof is already established via brokerProof.
        log.info("[AUTH] Client {} acknowledged AUTH - completing authentication", clientId);
        output.authenticateSuccessfully();
    }

    private Optional<String> getProperty(UserProperties props, String name) {
        List<UserProperty> list = props.asList();
        return list.stream()
            .filter(p -> name.equals(p.getName()))
            .map(UserProperty::getValue)
            .findFirst();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
