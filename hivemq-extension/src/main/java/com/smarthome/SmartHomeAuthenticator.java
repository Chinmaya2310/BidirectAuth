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

public class SmartHomeAuthenticator implements SimpleAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(SmartHomeAuthenticator.class);
    private final TokenValidator tokenValidator;

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
}
