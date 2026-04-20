#!/bin/bash

# Copy lib_certs.sh functions
source "/Users/chinmayakumarnayak/Desktop/Mutual authetication  and authorization/arrowhead-mqtt-project/core-java-spring/scripts/certificate_generation/lib_certs.sh"

# Create certificates folder
mkdir -p certificates
cd certificates

# Step 1 - Root CA
create_root_keystore \
  "root.p12" "arrowhead.eu"

# Step 2 - Smarthome Cloud
create_cloud_keystore \
  "root.p12" "arrowhead.eu" \
  "smarthome-cloud.p12" "smarthome.arrowhead.eu"

# Step 3 - Core Services
create_system_keystore \
  "root.p12" "arrowhead.eu" \
  "smarthome-cloud.p12" "smarthome.arrowhead.eu" \
  "serviceregistry.p12" "serviceregistry.smarthome.arrowhead.eu" \
  "dns:localhost,ip:127.0.0.1"

create_system_keystore \
  "root.p12" "arrowhead.eu" \
  "smarthome-cloud.p12" "smarthome.arrowhead.eu" \
  "authorization.p12" "authorization.smarthome.arrowhead.eu" \
  "dns:localhost,ip:127.0.0.1"

create_system_keystore \
  "root.p12" "arrowhead.eu" \
  "smarthome-cloud.p12" "smarthome.arrowhead.eu" \
  "orchestrator.p12" "orchestrator.smarthome.arrowhead.eu" \
  "dns:localhost,ip:127.0.0.1"

# Step 4 - Client Systems
create_system_keystore \
  "root.p12" "arrowhead.eu" \
  "smarthome-cloud.p12" "smarthome.arrowhead.eu" \
  "hivemq-broker.p12" "hivemq-broker.smarthome.arrowhead.eu" \
  "dns:localhost,ip:127.0.0.1"

create_system_keystore \
  "root.p12" "arrowhead.eu" \
  "smarthome-cloud.p12" "smarthome.arrowhead.eu" \
  "temperature-sensor.p12" "temperature-sensor.smarthome.arrowhead.eu" \
  "dns:localhost,ip:127.0.0.1"

create_system_keystore \
  "root.p12" "arrowhead.eu" \
  "smarthome-cloud.p12" "smarthome.arrowhead.eu" \
  "smart-thermostat.p12" "smart-thermostat.smarthome.arrowhead.eu" \
  "dns:localhost,ip:127.0.0.1"

# Step 5 - Sysop (admin certificate)
create_sysop_keystore \
  "root.p12" "arrowhead.eu" \
  "smarthome-cloud.p12" "smarthome.arrowhead.eu" \
  "sysop.p12" "sysop.smarthome.arrowhead.eu"

# Step 6 - Truststore
create_truststore \
  "truststore.p12" \
  "smarthome-cloud.crt" "smarthome.arrowhead.eu"

cd ..
echo "All certificates generated successfully"
echo "Files in certificates/:"
ls certificates/
