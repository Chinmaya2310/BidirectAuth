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
SYSTEM_NAME  = "sample-02"
SERVICE_NAME = "sample-publish"
CERT_FILE    = "certificates/sample-02.crt"
KEY_FILE     = "certificates/sample-02.key"
ORCHESTRATOR = "https://127.0.0.1:8441"

def get_pubkey_base64():
    with open("certificates/sample-02.pub") as f:
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
            "port": 9300,
            "authenticationInfo": pubkey
        },
        "requestedService": {
            "serviceDefinitionRequirement": SERVICE_NAME,
            "interfaceRequirements": ["HTTP-SECURE-JSON"],
            "securityRequirements": ["TOKEN"]
        },
        "orchestrationFlags": {"overrideStore": True}
    }
    print(f"[SAMPLE-02] Calling Orchestrator for: {SERVICE_NAME}")
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
    print(f"[SAMPLE-02] Broker: {broker_address}:{broker_port}")
    if not encrypted_token:
        raise Exception("No token received from Arrowhead")
    print(f"[SAMPLE-02] Token received from Arrowhead (encrypted for HiveMQ)")
    print(f"[SAMPLE-02] Token first 50 chars: {encrypted_token[:50]}...")
    return broker_address, broker_port, encrypted_token

def main():
    # Load Arrowhead's public key — trust anchor for broker credential validation
    with open('certificates/authorization.pub', 'rb') as f:
        arrowhead_pub_key = serialization.load_pem_public_key(f.read())
    print(f"[SAMPLE-02] Loaded Arrowhead public key for broker credential validation")

    print("=== Phase 1: Arrowhead Orchestration ===")
    broker, port, token = request_orchestration()

    print("\n=== Phase 2: Connect to HiveMQ with Arrowhead token ===")
    # Generate fresh nonce — 16 bytes = 32 hex chars
    client_nonce = secrets.token_hex(16)
    print(f"[SAMPLE-02] clientNonce: {client_nonce}")

    client = mqtt.Client(client_id=SYSTEM_NAME, protocol=mqtt.MQTTv5, reconnect_on_failure=False)
    # Plain TCP — no TLS setup needed
    # Broker identity is verified cryptographically via brokerProof below

    connect_props = mqtt.Properties(mqtt.PacketTypes.CONNECT)
    connect_props.UserProperty = [
        ("systemName",      SYSTEM_NAME),
        ("arrowheadToken",  token),
        ("clientNonce",     client_nonce)   # freshness — replay protection
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
        # === Mutual Auth: validate broker identity from CONNACK ===
        if props is None or not hasattr(props, "UserProperty"):
            print(f"[SAMPLE-02] ❌ CONNACK has no properties — fake broker? Disconnecting.")
            auth_fail(c, "CONNACK has no properties — fake broker? Disconnecting.")
            return

        user_props = dict(props.UserProperty or [])
        bn = user_props.get("brokerNonce")
        bp = user_props.get("brokerProof")
        bc = user_props.get("brokerCredential")

        if not (bn and bp and bc):
            print(f"[SAMPLE-02] ❌ CONNACK missing brokerNonce/brokerProof/brokerCredential — disconnecting")
            auth_fail(c, "CONNACK missing brokerNonce/brokerProof/brokerCredential — disconnecting")
            return

        print(f"[SAMPLE-02] brokerNonce received: {bn}")
        print(f"[SAMPLE-02] brokerCredential received ({len(bc)} chars)")

        # Step 1: Validate Broker-Credential-JWT using Arrowhead's public key
        # This proves Arrowhead vouches for this broker
        try:
            claims = jwt.decode(bc, arrowhead_pub_key, algorithms=["RS256"])
            print(f"[SAMPLE-02] ✅ Broker credential validated: {claims['sub']}")

            # Extract broker's RSA public key from the validated JWT
            broker_pub_pem = claims['brokerPub']
            broker_pub_key = serialization.load_pem_public_key(broker_pub_pem.encode('utf-8'))
            print(f"[SAMPLE-02] ✅ Broker public key extracted from validated credential")

        except jwt.InvalidSignatureError:
            print(f"[SAMPLE-02] ❌ Broker credential signature INVALID!")
            auth_fail(c, "Broker credential signature INVALID")
            return
        except jwt.ExpiredSignatureError:
            print(f"[SAMPLE-02] ❌ Broker credential EXPIRED! Run mk_broker_credential.py")
            auth_fail(c, "Broker credential EXPIRED! Run mk_broker_credential.py")
            return
        except Exception as e:
            print(f"[SAMPLE-02] ❌ Failed to validate broker credential: {e}")
            auth_fail(c, "Failed to validate broker credential: {e}")
            return

        # Step 2: Verify brokerProof = RSA signature over (clientNonce + brokerNonce)
        # This proves the broker holds the private key matching the public key above
        expected = (client_nonce + bn).encode("utf-8")
        try:
            broker_pub_key.verify(
                base64.b64decode(bp),
                expected,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            print(f"[SAMPLE-02] ✅ brokerProof VALID — broker identity confirmed")
            print(f"[SAMPLE-02] 🔒 MUTUAL AUTHENTICATION COMPLETE")
            auth_state["ok"] = True
            auth_state["reason"] = "verified"
            auth_done.set()
        except InvalidSignature:
            print(f"[SAMPLE-02] ❌ brokerProof INVALID — possible fake broker!")
            auth_fail(c, "brokerProof INVALID — possible fake broker")
            return

        if rc == 0:
            print(f"[SAMPLE-02] Connected to HiveMQ successfully")
        else:
            print(f"[SAMPLE-02] Connection failed rc={rc}")

    client.on_connect = on_connect
    client.connect(broker, PORT, 60, properties=connect_props)
    client.loop_start()
    if not auth_done.wait(timeout=10) or not auth_state["ok"]:
        print(f"[SAMPLE-02] ❌ Broker verification FAILED ({auth_state['reason']}) — aborting, no data sent")
        client.loop_stop()
        client.disconnect()
        sys.exit(1)

    print("\n=== Phase 3: Publishing data ===")
    while True:
        data = round(random.uniform(0, 1000), 1)
        pub_props = mqtt.Properties(mqtt.PacketTypes.PUBLISH)
        pub_props.UserProperty = [
            ("systemName",     SYSTEM_NAME),
            ("arrowheadToken", token)
        ]
        payload = json.dumps({
            "data":      data,
            "timestamp": time.time()
        })
        client.publish("room/temperature", payload, qos=1, properties=pub_props)
        print(f"[SAMPLE-02] Published: {data}")
        time.sleep(5)

if __name__ == "__main__":
    main()