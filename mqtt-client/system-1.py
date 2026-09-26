import time, random, json, sys, requests, warnings, secrets
warnings.filterwarnings("ignore")
sys.path.insert(0, ".")
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import base64
import jwt
import paho.mqtt.client as mqtt

BROKER       = "127.0.0.1"
PORT         = 1883
SYSTEM_NAME  = "system-1"
SERVICE_NAME = "service-1"
CERT_FILE    = "certificates/system-1.crt"
KEY_FILE     = "certificates/system-1.key"
ORCHESTRATOR = "https://127.0.0.1:8441"

def get_pubkey_base64():
    with open("certificates/system-1.pub") as f:
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
            "port": 9500,
            "authenticationInfo": ""
        },
        "requestedService": {
            "serviceDefinitionRequirement": SERVICE_NAME,
            "interfaceRequirements": ["HTTP-SECURE-JSON"],
            "securityRequirements": ["TOKEN"]
        },
        "orchestrationFlags": {"overrideStore": True}
    }
    print(f"[SENSOR] Calling Orchestrator for: {SERVICE_NAME}")
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
    # Get encrypted token - send as-is to HiveMQ
    # HiveMQ will decrypt it using its private key
    encrypted_token = auth_tokens.get("HTTP-SECURE-JSON")
    print(f"[SENSOR] Broker: {broker_address}:{broker_port}")
    if not encrypted_token:
        raise Exception("No token received from Arrowhead")
    print(f"[SENSOR] Token received from Arrowhead (encrypted for HiveMQ)")
    print(f"[SENSOR] Token first 50 chars: {encrypted_token[:50]}...")
    return broker_address, broker_port, encrypted_token

def main():
    # Load Arrowhead's public key (trust anchor for broker credential validation)
    with open('certificates/authorization.pub', 'rb') as f:
        arrowhead_pub_key = serialization.load_pem_public_key(f.read())
    print(f"[SENSOR] Loaded Arrowhead public key for broker credential validation")

    print("=== Phase 1: Arrowhead Orchestration ===")
    broker, port, token = request_orchestration()

    print("\n=== Phase 2: Connect to HiveMQ with Arrowhead token ===")
    client_nonce = secrets.token_hex(16)  # 16 bytes = 32 hex chars
    print(f"[SENSOR] clientNonce: {client_nonce}")

    client = mqtt.Client(client_id=SYSTEM_NAME, protocol=mqtt.MQTTv5, reconnect_on_failure=False)

    # Plain TCP — no TLS setup needed
    # Broker identity is verified cryptographically via brokerProof below

    connect_props = mqtt.Properties(mqtt.PacketTypes.CONNECT)
    connect_props.UserProperty = [
        ("systemName", SYSTEM_NAME),
        ("arrowheadToken", token),
        ("clientNonce", client_nonce)
    ]

    def on_connect(c, userdata, flags, rc, props=None):
        # === BidirectAuth: read brokerNonce + brokerProof from CONNACK ===
        if props is None or not hasattr(props, "UserProperty"):
            print(f"[SYSTEM-1] ❌ CONNACK has no properties — fake broker detected! Disconnecting.")
            c.disconnect()
            sys.exit(1)
        
        if props is not None and hasattr(props, "UserProperty"):
            user_props = dict(props.UserProperty or [])
            bn = user_props.get("brokerNonce")
            bp = user_props.get("brokerProof")
            bc = user_props.get("brokerCredential")
            
            if not (bn and bp and bc):
                print(f"[SYSTEM-1] ❌ CONNACK missing brokerNonce/brokerProof/brokerCredential — disconnecting")
                c.disconnect()
                sys.exit(1)
            
            print(f"[SENSOR] brokerNonce received: {bn}")
            print(f"[SENSOR] brokerCredential received ({len(bc)} chars)")
            
            # Step 1: Validate Broker-Credential-JWT signature using Arrowhead's public key
            try:
                claims = jwt.decode(bc, arrowhead_pub_key, algorithms=["RS256"])
                print(f"[SENSOR] ✅ Broker credential validated: {claims['sub']}")
                
                # Extract broker's public key from validated credential
                broker_pub_pem = claims['brokerPub']
                broker_pub_key = serialization.load_pem_public_key(broker_pub_pem.encode('utf-8'))
                print(f"[SENSOR] ✅ Broker public key extracted from validated credential")
                
            except jwt.InvalidSignatureError:
                print(f"[SENSOR] ❌ Broker credential signature INVALID!")
                c.disconnect()
                sys.exit(1)
            except jwt.ExpiredSignatureError:
                print(f"[SENSOR] ❌ Broker credential EXPIRED!")
                c.disconnect()
                sys.exit(1)
            except Exception as e:
                print(f"[SENSOR] ❌ Failed to validate broker credential: {e}")
                c.disconnect()
                sys.exit(1)
            
            # Step 2: Verify brokerProof using broker's public key from validated credential
            expected = (client_nonce + bn).encode("utf-8")
            try:
                broker_pub_key.verify(
                    base64.b64decode(bp),
                    expected,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
                print(f"[SENSOR] ✅ brokerProof VALID — broker identity confirmed")
                print(f"[SENSOR] 🔒 MUTUAL AUTHENTICATION COMPLETE")
            except InvalidSignature:
                print(f"[SENSOR] ❌ brokerProof INVALID!")
                c.disconnect()
                sys.exit(1)
        if rc == 0:
            print(f"[SENSOR] Connected to HiveMQ successfully")
        else:
            print(f"[SENSOR] Connection failed rc={rc}")

    client.on_connect = on_connect
    client.connect(broker, PORT, 60, properties=connect_props)
    client.loop_start()
    time.sleep(1)

    print("\n=== Phase 3: Publishing temperature data ===")
    while True:
        temperature = round(random.uniform(18.0, 30.0), 1)
        pub_props = mqtt.Properties(mqtt.PacketTypes.PUBLISH)
        pub_props.UserProperty = [
            ("systemName", SYSTEM_NAME),
            ("arrowheadToken", token)
        ]
        payload = json.dumps({
            "temperature": temperature,
            "unit": "celsius",
            "timestamp": time.time()
        })
        client.publish("room/service-1", payload, qos=1, properties=pub_props)
        print(f"[SENSOR] Published: {temperature}C")
        time.sleep(5)

if __name__ == "__main__":
    main()