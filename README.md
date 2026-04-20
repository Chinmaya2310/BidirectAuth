# SmartHome Demo — Eclipse Arrowhead + HiveMQ IoT Security

A full implementation of JWT-based MQTT authorization using Eclipse Arrowhead 4.6.2 and HiveMQ CE 2024.3.

## Overview

This project implements a secure smart home IoT system where:
- A **temperature sensor** publishes room temperature data
- A **smart thermostat** subscribes and controls heating/cooling
- **Eclipse Arrowhead** handles service registration, authorization, and token issuance
- **HiveMQ** acts as the MQTT broker and enforces per-packet JWT authorization

## Security Flow

```
temperature-sensor
  → calls Arrowhead Orchestrator (with SSL certificate)
  → Orchestrator checks Service Registry + Authorization
  → Arrowhead issues JWE token encrypted with HiveMQ broker's public key
  → sensor connects to HiveMQ with token in MQTT 5 User Properties
  → HiveMQ extension decrypts JWE using broker private key
  → HiveMQ verifies inner JWT using Arrowhead's public key
  → sensor publishes temperature data
  → smart-thermostat receives data and adjusts heating/cooling
```

## Project Structure

```
smarthome-demo/
├── serviceregistry.jar        # Arrowhead Service Registry
├── authorization.jar          # Arrowhead Authorization
├── orchestrator.jar           # Arrowhead Orchestrator
├── certificates/              # SSL certificates for all systems
├── config/                    # Config files for Arrowhead services
│   ├── serviceregistry/
│   ├── authorization/
│   └── orchestrator/
├── hivemq-ce-2024.3/          # HiveMQ broker + extension
├── hivemq-extension/          # Extension source code (Java/Maven)
│   └── src/main/java/com/smarthome/
│       ├── SmartHomeExtensionMain.java   # Entry point
│       ├── KeyLoader.java                # Fetches Arrowhead public key
│       ├── TokenValidator.java           # JWE decryption + JWT verification
│       ├── SmartHomeAuthenticator.java   # Handles CONNECT packets
│       ├── SmartHomeAuthorizer.java      # Handles PUBLISH/SUBSCRIBE packets
│       └── SmartHomePublishInterceptor.java # Strips JWT from outbound messages
├── mqtt-client/
│   ├── temperature_sensor.py  # Publisher client
│   └── smart_thermostat.py    # Subscriber client
└── mk_certs.sh                # Certificate generation script
```

## Prerequisites

- Java 17+
- Maven 3.8+
- Python 3.10+
- MySQL 8.0+
- HiveMQ CE 2024.3

## Setup

### Step 1 — Generate Certificates

```bash
bash mk_certs.sh
```

This generates a full certificate chain:
- Root CA
- Smarthome cloud certificate
- Individual certificates for each service and client system

### Step 2 — Configure MySQL

Ensure MySQL is running and the Arrowhead database exists. The default credentials are already set in the config files.

### Step 3 — Build HiveMQ Extension

```bash
cd hivemq-extension
mvn clean package -q
cd ..

# Install extension into HiveMQ
unzip -q hivemq-extension/target/smarthome-auth-extension-1.0.0-distribution.zip \
  -d hivemq-ce-2024.3/extensions/

# Add ServiceLoader file
mkdir -p /tmp/svc/META-INF/services
echo "com.smarthome.SmartHomeExtensionMain" > \
  /tmp/svc/META-INF/services/com.hivemq.extension.sdk.api.ExtensionMain
cd /tmp/svc
jar uf "PATH_TO_PROJECT/hivemq-ce-2024.3/extensions/smarthome-auth-extension/smarthome-auth-extension-1.0.0.jar" \
  META-INF/services/com.hivemq.extension.sdk.api.ExtensionMain
cd PATH_TO_PROJECT
```

### Step 4 — Install Python Dependencies

```bash
pip3 install paho-mqtt requests jwcrypto cryptography
```

## Running the Project

Open 6 terminal tabs and run one command in each. Always wait for the success message before proceeding to the next.

### Terminal 1 — Service Registry

```bash
cd smarthome-demo
java -jar serviceregistry.jar \
  --spring.config.location=config/serviceregistry/application.properties
```

Wait for: `Started ServiceRegistryMain`

### Terminal 2 — Authorization

```bash
cd smarthome-demo
java -jar authorization.jar \
  --spring.config.location=config/authorization/application.properties
```

Wait for: `Started AuthorizationMain`

### Terminal 3 — Orchestrator

```bash
cd smarthome-demo
java -jar orchestrator.jar \
  --spring.config.location=config/orchestrator/application.properties
```

Wait for: `Started OrchestratorMain`

### Terminal 4 — HiveMQ

```bash
cd smarthome-demo

ARROWHEAD_AUTH_URL="https://127.0.0.1:8445" \
BROKER_KEYSTORE="PATH_TO_PROJECT/certificates/hivemq-broker.p12" \
KEYSTORE_PASSWORD="123456" \
TRUSTSTORE="PATH_TO_PROJECT/certificates/truststore.p12" \
TRUSTSTORE_PASSWORD="123456" \
./hivemq-ce-2024.3/bin/run.sh
```

Wait for: `Broker private key loaded` and `SmartHome Auth Extension started successfully`

### Terminal 5 — Temperature Sensor

```bash
cd smarthome-demo
python3 mqtt-client/temperature_sensor.py
```

Wait for: `Connected to HiveMQ successfully`

### Terminal 6 — Smart Thermostat

```bash
cd smarthome-demo
python3 mqtt-client/smart_thermostat.py
```

Wait for: `Subscribed to room/temperature`

## Expected Output

**Temperature Sensor:**
```
=== Phase 1: Arrowhead Orchestration ===
[SENSOR] Calling Orchestrator for: temperature-reading
[SENSOR] Broker: 127.0.0.1:1883
[SENSOR] Token received from Arrowhead (encrypted for HiveMQ)
=== Phase 2: Connect to HiveMQ with Arrowhead token ===
[SENSOR] Connected to HiveMQ successfully
=== Phase 3: Publishing temperature data ===
[SENSOR] Published: 22.1C
[SENSOR] Published: 25.6C
```

**Smart Thermostat:**
```
=== Phase 1: Arrowhead Orchestration ===
[THERMOSTAT] Calling Orchestrator for: temperature-subscribe
[THERMOSTAT] Broker: 127.0.0.1:1883
[THERMOSTAT] Token received from Arrowhead
=== Phase 2: Connect to HiveMQ ===
[THERMOSTAT] Connected to HiveMQ successfully
[THERMOSTAT] Subscribed to room/temperature
[THERMOSTAT] Received temperature: 22.1C
[THERMOSTAT] Temperature comfortable
[THERMOSTAT] Received temperature: 27.3C
[THERMOSTAT] Too hot! Turning AC on
```

## Arrowhead Services

| Service | Port | Mode |
|---|---|---|
| Service Registry | 8443 | HTTPS (SECURED) |
| Authorization | 8445 | HTTPS (SECURED) |
| Orchestrator | 8441 | HTTPS (SECURED) |
| HiveMQ MQTT Broker | 1883 | TCP |

## Registered Systems

| System | Port | Role |
|---|---|---|
| hivemq-broker | 1883 | MQTT broker |
| temperature-sensor | 9100 | Publisher |
| smart-thermostat | 9101 | Subscriber |

## Security Details

- **Certificate Authority:** Custom Arrowhead root CA
- **Token Type:** JWE (RSA-OAEP-256 + A256CBC-HS512)
- **Inner JWT Algorithm:** RS256
- **Token Issuer:** Arrowhead Authorization service
- **Token Verification:** Arrowhead's RSA public key (fetched at HiveMQ startup)
- **Per-packet Authorization:** Every PUBLISH and SUBSCRIBE validated

## How It Exceeds the Base Paper

The base paper describes JWT signing (RS256). This implementation uses JWE encryption — an additional security layer where the token is encrypted specifically for HiveMQ broker using its public key. A stolen token is useless without the broker's private key.
