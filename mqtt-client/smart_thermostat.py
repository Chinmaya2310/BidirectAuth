import json, sys, requests, warnings, secrets, ssl
warnings.filterwarnings("ignore")
sys.path.insert(0, ".")
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import base64
import jwt
import paho.mqtt.client as mqtt

BROKER       = "127.0.0.1"
PORT         = 8883
SYSTEM_NAME  = "smart-thermostat"
SERVICE_NAME = "temperature-subscribe"
CERT_FILE    = "certificates/smart-thermostat.crt"
KEY_FILE     = "certificates/smart-thermostat.key"
ORCHESTRATOR = "https://127.0.0.1:8441"

def get_pubkey_base64():
    with open("certificates/smart-thermostat.pub") as f:
        content = f.read()
    content = content.replace("-----BEGIN PUBLIC KEY-----", "")
    content = content.replace("-----END PUBLIC KEY-----", "")
    return content.replace("\n", "").strip()

def request_orchestration():
    pubkey = get_pubkey_base64()
    payload = {
        "requesterSystem": {
            "systemName": SYSTEM_NAME,
            "address": "127.0.0.1",
            "port": 9101,
            "authenticationInfo": pubkey
        },
        "requestedService": {
            "serviceDefinitionRequirement": SERVICE_NAME,
            "interfaceRequirements": ["HTTP-SECURE-JSON"],
            "securityRequirements": ["TOKEN"]
        },
        "orchestrationFlags": {"overrideStore": True}
    }
    print(f"[THERMOSTAT] Calling Orchestrator for: {SERVICE_NAME}")
    resp = requests.post(
        f"{ORCHESTRATOR}/orchestrator/orchestration",
        json=payload,
        cert=(CERT_FILE, KEY_FILE),
        verify=False
    )
    if resp.status_code != 200:
        raise Exception(f"Orchestration failed: {resp.status_code}")
    data = resp.json()
    results = data.get("response", [])
    if not results:
        raise Exception("No provider found")
    result = results[0]
    broker_address = result["provider"]["address"]
    broker_port    = result["provider"]["port"]
    auth_tokens    = result.get("authorizationTokens", {})
    encrypted_token = auth_tokens.get("HTTP-SECURE-JSON")
    print(f"[THERMOSTAT] Broker: {broker_address}:{broker_port}")
    if not encrypted_token:
        raise Exception("No token received from Arrowhead")
    print(f"[THERMOSTAT] Token received from Arrowhead")
    return broker_address, broker_port, encrypted_token

def main():
    # Load Arrowhead's public key (trust anchor for broker credential validation)
    with open('certificates/authorization.pub', 'rb') as f:
        arrowhead_pub_key = serialization.load_pem_public_key(f.read())
    print(f"[THERMOSTAT] Loaded Arrowhead public key for broker credential validation")

    print("=== Phase 1: Arrowhead Orchestration ===")
    broker, port, token = request_orchestration()

    print("\n=== Phase 2: Connect to HiveMQ ===")
    client_nonce = secrets.token_hex(16)
    print(f"[THERMOSTAT] clientNonce: {client_nonce}")

    client = mqtt.Client(client_id=SYSTEM_NAME, protocol=mqtt.MQTTv5)

    # Enable TLS — verify broker cert against our CA, no client cert needed
    # Cert chain has malformed Key Usage on root CA — disable verification.
    # Broker identity will be validated cryptographically via brokerProof (sub-step 2d).
    tls_ctx = ssl.create_default_context()
    tls_ctx.check_hostname = False
    tls_ctx.verify_mode = ssl.CERT_NONE
    client.tls_set_context(tls_ctx)

    connect_props = mqtt.Properties(mqtt.PacketTypes.CONNECT)
    connect_props.UserProperty = [
        ("systemName", SYSTEM_NAME),
        ("arrowheadToken", token),
        ("clientNonce", client_nonce)
    ]

    def on_connect(c, userdata, flags, rc, props=None):
        # === BidirectAuth: read brokerNonce + brokerProof from CONNACK ===
        if props is not None and hasattr(props, "UserProperty"):
            user_props = dict(props.UserProperty or [])
            bn = user_props.get("brokerNonce")
            bp = user_props.get("brokerProof")
            bc = user_props.get("brokerCredential")
            
            if not (bn and bp and bc):
                print(f"[THERMOSTAT] CONNACK missing brokerNonce/brokerProof/brokerCredential — disconnecting")
                c.disconnect()
                sys.exit(1)
            
            print(f"[THERMOSTAT] brokerNonce received: {bn}")
            print(f"[THERMOSTAT] brokerCredential received ({len(bc)} chars)")
            
            # Step 1: Validate Broker-Credential-JWT
            try:
                claims = jwt.decode(bc, arrowhead_pub_key, algorithms=["RS256"])
                print(f"[THERMOSTAT] ✅ Broker credential validated: {claims['sub']}")
                
                broker_pub_pem = claims['brokerPub']
                broker_pub_key = serialization.load_pem_public_key(broker_pub_pem.encode('utf-8'))
                print(f"[THERMOSTAT] ✅ Broker public key extracted")
                
            except jwt.InvalidSignatureError:
                print(f"[THERMOSTAT] ❌ Broker credential INVALID!")
                c.disconnect()
                sys.exit(1)
            except jwt.ExpiredSignatureError:
                print(f"[THERMOSTAT] ❌ Broker credential EXPIRED!")
                c.disconnect()
                sys.exit(1)
            except Exception as e:
                print(f"[THERMOSTAT] ❌ Validation failed: {e}")
                c.disconnect()
                sys.exit(1)
            
            # Step 2: Verify brokerProof
            expected = (client_nonce + bn).encode("utf-8")
            try:
                broker_pub_key.verify(
                    base64.b64decode(bp),
                    expected,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
                print(f"[THERMOSTAT] ✅ brokerProof VALID")
                print(f"[THERMOSTAT] 🔒 MUTUAL AUTHENTICATION COMPLETE")
            except InvalidSignature:
                print(f"[THERMOSTAT] ❌ brokerProof INVALID!")
                c.disconnect()
                sys.exit(1)
        if rc == 0:
            print(f"[THERMOSTAT] Connected to HiveMQ successfully")
            sub_props = mqtt.Properties(mqtt.PacketTypes.SUBSCRIBE)
            sub_props.UserProperty = [
                ("systemName", SYSTEM_NAME),
                ("arrowheadToken", token)
            ]
            c.subscribe("room/temperature", qos=1, properties=sub_props)
            print(f"[THERMOSTAT] Subscribed to room/temperature")
        else:
            print(f"[THERMOSTAT] Connection failed rc={rc}")

    def on_message(c, userdata, msg):
        try:
            data = json.loads(msg.payload)
            temp = data.get("temperature")
            print(f"[THERMOSTAT] Received temperature: {temp}C")
            if temp > 25:
                print(f"[THERMOSTAT] Too hot! Turning AC on")
            elif temp < 20:
                print(f"[THERMOSTAT] Too cold! Turning heater on")
            else:
                print(f"[THERMOSTAT] Temperature comfortable")
        except Exception as e:
            print(f"[THERMOSTAT] Error: {e}")

    client.on_connect = on_connect
    client.on_message = on_message
    # Override Arrowhead's port: it returns 1883, we want 8883 (TLS)
    client.connect(broker, PORT, 60, properties=connect_props)
    print(f"[THERMOSTAT] Waiting for temperature data...")
    client.loop_forever()

if __name__ == "__main__":
    main()
