package com.smarthome;

import com.hivemq.extension.sdk.api.interceptor.publish.PublishOutboundInterceptor;
import com.hivemq.extension.sdk.api.interceptor.publish.parameter.PublishOutboundInput;
import com.hivemq.extension.sdk.api.interceptor.publish.parameter.PublishOutboundOutput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SmartHomePublishInterceptor implements PublishOutboundInterceptor {

    private static final Logger log = LoggerFactory.getLogger(SmartHomePublishInterceptor.class);

    @Override
    public void onOutboundPublish(PublishOutboundInput input, PublishOutboundOutput output) {
        try {
            // Strip all User Properties from outbound message
            output.getPublishPacket().getUserProperties().clear();
            log.debug("[INTERCEPTOR] Stripped JWT from outbound PUBLISH");
        } catch (Exception e) {
            log.warn("[INTERCEPTOR] Could not strip User Properties: {}", e.getMessage());
        }
    }
}
