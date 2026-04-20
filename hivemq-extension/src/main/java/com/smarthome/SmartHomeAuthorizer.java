package com.smarthome;

import com.hivemq.extension.sdk.api.auth.PublishAuthorizer;
import com.hivemq.extension.sdk.api.auth.SubscriptionAuthorizer;
import com.hivemq.extension.sdk.api.auth.parameter.PublishAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.PublishAuthorizerOutput;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerOutput;
import com.hivemq.extension.sdk.api.packets.general.UserProperties;
import com.hivemq.extension.sdk.api.packets.general.UserProperty;
import com.hivemq.extension.sdk.api.packets.publish.AckReasonCode;
import com.hivemq.extension.sdk.api.packets.subscribe.SubackReasonCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.List;
import java.util.Optional;

public class SmartHomeAuthorizer implements PublishAuthorizer, SubscriptionAuthorizer {

    private static final Logger log = LoggerFactory.getLogger(SmartHomeAuthorizer.class);
    private final TokenValidator tokenValidator;

    public SmartHomeAuthorizer(TokenValidator tokenValidator) {
        this.tokenValidator = tokenValidator;
    }

    @Override
    public void authorizePublish(PublishAuthorizerInput input, PublishAuthorizerOutput output) {
        String clientId = input.getClientInformation().getClientId();
        String topic = input.getPublishPacket().getTopic();
        UserProperties props = input.getPublishPacket().getUserProperties();

        Optional<String> token = getToken(props);

        // No token - deny
        if (token.isEmpty()) {
            log.warn("[PUBLISH] DENIED {} - no token", clientId);
            output.failAuthorization(AckReasonCode.NOT_AUTHORIZED);
            return;
        }

        String systemName = tokenValidator.peekConsumerName(token.get());
        if (systemName == null) systemName = clientId;

        TokenValidator.ValidationResult result =
            tokenValidator.validatePacket(token.get(), systemName, topic, "PUBLISH");

        if (result.valid()) {
            log.info("[PUBLISH] ALLOWED client={} topic={}", clientId, topic);
            output.authorizeSuccessfully();
        } else {
            log.warn("[PUBLISH] DENIED client={} topic={} reason={}", clientId, topic, result.reason());
            output.failAuthorization(AckReasonCode.NOT_AUTHORIZED);
        }
    }

    @Override
    public void authorizeSubscribe(SubscriptionAuthorizerInput input,
                                   SubscriptionAuthorizerOutput output) {
        String clientId = input.getClientInformation().getClientId();
        String topic = input.getSubscription().getTopicFilter();
        UserProperties props = input.getUserProperties();

        Optional<String> token = getToken(props);

        // No token - deny
        if (token.isEmpty()) {
            log.warn("[SUBSCRIBE] DENIED {} - no token", clientId);
            output.failAuthorization(SubackReasonCode.NOT_AUTHORIZED);
            return;
        }

        String systemName = tokenValidator.peekConsumerName(token.get());
        if (systemName == null) systemName = clientId;

        TokenValidator.ValidationResult result =
            tokenValidator.validatePacket(token.get(), systemName, topic, "SUBSCRIBE");

        if (result.valid()) {
            log.info("[SUBSCRIBE] ALLOWED client={} topic={}", clientId, topic);
            output.authorizeSuccessfully();
        } else {
            log.warn("[SUBSCRIBE] DENIED client={} topic={} reason={}",
                clientId, topic, result.reason());
            output.failAuthorization(SubackReasonCode.NOT_AUTHORIZED);
        }
    }

    private Optional<String> getToken(UserProperties props) {
        List<UserProperty> list = props.asList();
        return list.stream()
            .filter(p -> "arrowheadToken".equals(p.getName()))
            .map(UserProperty::getValue)
            .findFirst();
    }
}
