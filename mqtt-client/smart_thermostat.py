import json, sys, requests, warnings
warnings.filterwarnings("ignore")
sys.path.insert(0, ".")
import paho.mqtt.client as mqtt

BROKER       = "127.0.0.1"
PORT         = 1883
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
    print("=== Phase 1: Arrowhead Orchestration ===")
    broker, port, token = request_orchestration()

    print("\n=== Phase 2: Connect to HiveMQ ===")
    client = mqtt.Client(client_id=SYSTEM_NAME, protocol=mqtt.MQTTv5)
    connect_props = mqtt.Properties(mqtt.PacketTypes.CONNECT)
    connect_props.UserProperty = [
        ("systemName", SYSTEM_NAME),
        ("arrowheadToken", token)
    ]

    def on_connect(c, userdata, flags, rc, props=None):
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
    client.connect(broker, port, 60, properties=connect_props)
    print(f"[THERMOSTAT] Waiting for temperature data...")
    client.loop_forever()

if __name__ == "__main__":
    main()
