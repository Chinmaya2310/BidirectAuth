package com.smarthome;

import com.hivemq.extension.sdk.api.ExtensionMain;
import com.hivemq.extension.sdk.api.parameter.ExtensionStartInput;
import com.hivemq.extension.sdk.api.parameter.ExtensionStartOutput;
import com.hivemq.extension.sdk.api.parameter.ExtensionStopInput;
import com.hivemq.extension.sdk.api.parameter.ExtensionStopOutput;
import com.hivemq.extension.sdk.api.services.Services;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SmartHomeExtensionMain implements ExtensionMain {

    private static final Logger log = LoggerFactory.getLogger(SmartHomeExtensionMain.class);

    @Override
    public void extensionStart(ExtensionStartInput input, ExtensionStartOutput output) {
        try {
            String authUrl            = System.getenv().getOrDefault("ARROWHEAD_AUTH_URL", "https://127.0.0.1:8445");
            String brokerKeystore     = System.getenv().getOrDefault("BROKER_KEYSTORE", "certificates/hivemq-broker.p12");
            String keystorePassword   = System.getenv().getOrDefault("KEYSTORE_PASSWORD", "123456");
            String truststore         = System.getenv().getOrDefault("TRUSTSTORE", "certificates/truststore.p12");
            String truststorePassword = System.getenv().getOrDefault("TRUSTSTORE_PASSWORD", "123456");

            log.info("=== SmartHome Auth Extension starting ===");
            log.info("Arrowhead URL: {}", authUrl);
            log.info("Broker keystore: {}", brokerKeystore);

            // Step 1 - Fetch Arrowhead public key
            KeyLoader keyLoader = new KeyLoader();
            java.security.interfaces.RSAPublicKey publicKey =
                keyLoader.loadPublicKeyFromArrowhead(
                    authUrl, brokerKeystore, keystorePassword,
                    truststore, truststorePassword);

            // Step 2 - Create token validator
            TokenValidator tokenValidator = new TokenValidator(publicKey);

            // Step 3 - Load broker private key for JWE decryption
            log.info("Loading broker private key...");
            tokenValidator.loadBrokerPrivateKey(brokerKeystore, keystorePassword);

            // Step 4 - Register authenticator
            Services.securityRegistry().setEnhancedAuthenticatorProvider(
                p -> new SmartHomeAuthenticator(tokenValidator));

            // Step 5 - Register authorizer
            SmartHomeAuthorizer authorizer = new SmartHomeAuthorizer(tokenValidator);
            Services.securityRegistry().setAuthorizerProvider(p -> authorizer);

            // Step 6 - Register interceptor
            SmartHomePublishInterceptor interceptor = new SmartHomePublishInterceptor();
            Services.initializerRegistry().setClientInitializer(
                (initInput, clientContext) ->
                    clientContext.addPublishOutboundInterceptor(interceptor));

            log.info("=== SmartHome Auth Extension started successfully ===");

        } catch (Exception e) {
            log.error("Failed to start SmartHome Auth Extension", e);
            output.preventExtensionStartup("Initialization failed: " + e.getMessage());
        }
    }

    @Override
    public void extensionStop(ExtensionStopInput input, ExtensionStopOutput output) {
        log.info("SmartHome Auth Extension stopped");
    }
}
