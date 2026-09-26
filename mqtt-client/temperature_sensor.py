import time, random, json, sys, requests, warnings, secrets
warnings.filterwarnings("ignore")
sys.path.insert(0, ".")
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import base64
import jwt
import threading
import paho.mqtt.client as mqtt

BROKER       = "127.0.0.1"
PORT         = 1883
SYSTEM_NAME  = "temperature-sensor"
SERVICE_NAME = "temperature-reading"
CERT_FILE    = "certificates/temperature-sensor.crt"
KEY_FILE     = "certificates/temperature-sensor.key"
ORCHESTRATOR = "https://127.0.0.1:8441"

def get_pubkey_base64():
    with open("certificates/temperature-sensor.pub") as f:
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
            "port": 9100,
            "authenticationInfo": pubkey
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

    client = mqtt.Client(client_id=SYSTEM_NAME, protocol=mqtt.MQTTv5)

    # Plain TCP — no TLS setup needed
    # Broker identity is verified cryptographically via brokerProof below

    connect_props = mqtt.Properties(mqtt.PacketTypes.CONNECT)
    connect_props.UserProperty = [
        ("systemName", SYSTEM_NAME),
        ("arrowheadToken", token),
        ("clientNonce", client_nonce)
    ]

    # === BidirectAuth gate ===
    # on_connect runs on the paho network thread; sys.exit() there raises SystemExit
    # in that thread only and cannot stop main(). Record the verdict here and let the
    # main thread enforce it before any data is sent.
    auth_done  = threading.Event()
    auth_state = {"ok": False, "reason": "no CONNACK received"}

    def auth_fail(c, reason):
        auth_state["ok"] = False
        auth_state["reason"] = reason
        auth_done.set()
        c.disconnect()

    def on_connect(c, userdata, flags, rc, props=None):
        # === BidirectAuth: read brokerNonce + brokerProof from CONNACK ===
        if props is None or not getattr(props, "UserProperty", None):
            print(f"[SENSOR] ❌ CONNACK carried no BidirectAuth properties — rejecting broker")
            auth_fail(c, "CONNACK carried no BidirectAuth properties")
            return

        user_props = dict(props.UserProperty or [])
        bn = user_props.get("brokerNonce")
        bp = user_props.get("brokerProof")
        bc = user_props.get("brokerCredential")
        
        if not (bn and bp and bc):
            print(f"[SENSOR] CONNACK missing brokerNonce/brokerProof/brokerCredential — disconnecting")
            auth_fail(c, "CONNACK missing brokerNonce/brokerProof/brokerCredential — disconnecting")
            return
        
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
            auth_fail(c, "Broker credential signature INVALID")
            return
        except jwt.ExpiredSignatureError:
            print(f"[SENSOR] ❌ Broker credential EXPIRED!")
            auth_fail(c, "Broker credential EXPIRED")
            return
        except Exception as e:
            print(f"[SENSOR] ❌ Failed to validate broker credential: {e}")
            auth_fail(c, "Failed to validate broker credential: {e}")
            return
        
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
            auth_state["ok"] = True
            auth_state["reason"] = "verified"
            auth_done.set()
        except InvalidSignature:
            print(f"[SENSOR] ❌ brokerProof INVALID!")
            auth_fail(c, "brokerProof INVALID")
            return
        if rc == 0:
            print(f"[SENSOR] Connected to HiveMQ successfully")
        else:
            print(f"[SENSOR] Connection failed rc={rc}")

    client.on_connect = on_connect
    client.connect(broker, PORT, 60, properties=connect_props)
    client.loop_start()
    if not auth_done.wait(timeout=10) or not auth_state["ok"]:
        print(f"[SENSOR] ❌ Broker verification FAILED ({auth_state['reason']}) — aborting, no data sent")
        client.loop_stop()
        client.disconnect()
        sys.exit(1)

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
        client.publish("room/temperature", payload, qos=1, properties=pub_props)
        print(f"[SENSOR] Published: {temperature}C")
        time.sleep(5)

if __name__ == "__main__":
    main()