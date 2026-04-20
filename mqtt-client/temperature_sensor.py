import time, random, json, sys, requests, warnings
warnings.filterwarnings("ignore")
sys.path.insert(0, ".")
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
    print("=== Phase 1: Arrowhead Orchestration ===")
    broker, port, token = request_orchestration()

    print("\n=== Phase 2: Connect to HiveMQ with Arrowhead token ===")
    client = mqtt.Client(client_id=SYSTEM_NAME, protocol=mqtt.MQTTv5)
    connect_props = mqtt.Properties(mqtt.PacketTypes.CONNECT)
    connect_props.UserProperty = [
        ("systemName", SYSTEM_NAME),
        ("arrowheadToken", token)
    ]

    def on_connect(c, userdata, flags, rc, props=None):
        if rc == 0:
            print(f"[SENSOR] Connected to HiveMQ successfully")
        else:
            print(f"[SENSOR] Connection failed rc={rc}")

    client.on_connect = on_connect
    client.connect(broker, port, 60, properties=connect_props)
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
        client.publish("room/temperature", payload, qos=1, properties=pub_props)
        print(f"[SENSOR] Published: {temperature}C")
        time.sleep(5)

if __name__ == "__main__":
    main()
