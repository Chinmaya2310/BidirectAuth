package com.smarthome;

import com.hivemq.extension.sdk.api.auth.EnhancedAuthenticator;
import com.hivemq.extension.sdk.api.auth.parameter.EnhancedAuthConnectInput;
import com.hivemq.extension.sdk.api.auth.parameter.EnhancedAuthInput;
import com.hivemq.extension.sdk.api.auth.parameter.EnhancedAuthOutput;
import com.hivemq.extension.sdk.api.packets.general.DisconnectedReasonCode;
import com.hivemq.extension.sdk.api.packets.general.ModifiableUserProperties;
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

    private final TokenValidator tokenValidator;

    public SmartHomeAuthenticator(TokenValidator tokenValidator) {
        this.tokenValidator = tokenValidator;
    }

    @Override
    public void onConnect(EnhancedAuthConnectInput input, EnhancedAuthOutput output) {
        String clientId = input.getClientInformation().getClientId();
        log.info("[CONNECT] Client: {}", clientId);

        // Read User Properties from CONNECT
        UserProperties props = input.getConnectPacket().getUserProperties();
        Optional<String> systemName = getProperty(props, "systemName");
        Optional<String> token = getProperty(props, "arrowheadToken");
        Optional<String> clientNonce = getProperty(props, "clientNonce");

        if (clientNonce.isPresent()) {
            log.info("[CONNECT] clientNonce: {}", clientNonce.get());
        } else {
            log.warn("[CONNECT] No clientNonce - old client?");
        }

        // Required-property checks
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

        // Step 6 in the diagram - validate Client-JWE token
        TokenValidator.ValidationResult result =
            tokenValidator.validateConnect(token.get(), systemName.get());
        if (!result.valid()) {
            log.warn("[CONNECT] REJECTED client={} reason={}", clientId, result.reason());
            output.failAuthentication(DisconnectedReasonCode.NOT_AUTHORIZED, result.reason());
            return;
        }
        log.info("[CONNECT] Token valid for client={}", clientId);

        // ===== BidirectAuth Step 4 (CONNACK transport) =====
        // Generate brokerNonce + sign brokerProof = sign(clientNonce || brokerNonce, broker.priv)
        // Attach both to CONNACK User Properties.
        // Per design notes: AUTH packet would be the spec-compliant transport, but Python MQTT
        // libraries do not support AUTH-packet handling, so we use CONNACK User Properties.
        // Cryptographic guarantees are identical.
        if (clientNonce.isEmpty()) {
            log.warn("[CONNECT] No clientNonce — skipping BidirectAuth, allowing legacy client");
            output.authenticateSuccessfully();
            return;
        }

        try {
            byte[] brokerNonceBytes = new byte[16];
            secureRandom.nextBytes(brokerNonceBytes);
            String brokerNonce = bytesToHex(brokerNonceBytes);

            String concatenated = clientNonce.get() + brokerNonce;
            RSAPrivateKey brokerPriv = tokenValidator.getBrokerPrivateKey();
            if (brokerPriv == null) {
                log.error("[AUTH] broker.priv not loaded — cannot sign brokerProof");
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

            // Attach to CONNACK User Properties
            ModifiableUserProperties outboundProps = output.getOutboundUserProperties();
            outboundProps.addUserProperty("brokerNonce", brokerNonce);
            outboundProps.addUserProperty("brokerProof", brokerProof);

            log.info("[CONNECT] ACCEPTED client={} (CONNACK carries BidirectAuth proof)", clientId);
            output.authenticateSuccessfully();

        } catch (Exception e) {
            log.error("[AUTH] Failed to generate brokerProof for client={}: {}",
                    clientId, e.getMessage(), e);
            output.failAuthentication(DisconnectedReasonCode.SERVER_BUSY,
                    "BidirectAuth signing failed");
        }
    }

    @Override
    public void onAuth(EnhancedAuthInput input, EnhancedAuthOutput output) {
        // Path B does not use AUTH packets. Any AUTH received is unexpected.
        log.warn("[AUTH] Unexpected AUTH packet — disconnecting");
        output.failAuthentication(DisconnectedReasonCode.NOT_AUTHORIZED,
                "AUTH not supported in this configuration");
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
