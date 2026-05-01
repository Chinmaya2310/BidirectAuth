"""
mk_broker_credential.py — One-time broker credential issuer.

In a production deployment, this script runs ONCE on a secured ops machine that
holds Arrowhead's private key. It signs a JWT that vouches for a particular
broker's identity (broker name, URL, and public key), and outputs the JWT to a
file that ops then deploys to the broker.

The broker reads this file at startup, never has access to Arrowhead's private
key, and forwards the credential to clients during CONNACK so clients can verify
the broker is Arrowhead-registered.
"""

import sys
import time
import jwt  # PyJWT
from cryptography.hazmat.primitives.serialization import (
    pkcs12, load_pem_public_key, Encoding, PublicFormat
)

ARROWHEAD_KEYSTORE = "certificates/authorization.p12"
ARROWHEAD_KEYSTORE_PWD = b"123456"

BROKER_PUB_PEM_PATH = "certificates/hivemq-broker.pub"
OUTPUT_TOKEN_PATH = "certificates/hivemq-broker.token"

# Broker identity
BROKER_NAME = "hivemq-broker.smarthome.demo"
BROKER_URL  = "127.0.0.1:8883"

# Token validity (24 hours)
TTL_SECONDS = 24 * 60 * 60


def main():
    # 1. Load Arrowhead's private key (signing authority)
    with open(ARROWHEAD_KEYSTORE, "rb") as f:
        arrowhead_priv, _, _ = pkcs12.load_key_and_certificates(
            f.read(), ARROWHEAD_KEYSTORE_PWD
        )
    if arrowhead_priv is None:
        sys.exit("ERROR: could not extract private key from Arrowhead keystore")

    # 2. Load the broker's public key (this is what we're vouching for)
    with open(BROKER_PUB_PEM_PATH, "rb") as f:
        broker_pub_pem_bytes = f.read()

    # Sanity check: parse it to confirm it's valid PEM
    broker_pub = load_pem_public_key(broker_pub_pem_bytes)
    # Re-serialize to canonical PEM so it round-trips cleanly
    broker_pub_pem_canonical = broker_pub.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")

    # 3. Build claims
    now = int(time.time())
    claims = {
        "iss":       "Arrowhead",
        "sub":       BROKER_NAME,
        "brokerUrl": BROKER_URL,
        "brokerPub": broker_pub_pem_canonical,
        "iat":       now,
        "nbf":       now,
        "exp":       now + TTL_SECONDS,
    }

    # 4. Sign with Arrowhead.priv (RS256)
    token = jwt.encode(claims, arrowhead_priv, algorithm="RS256")

    # 5. Write output
    with open(OUTPUT_TOKEN_PATH, "w") as f:
        f.write(token)

    print(f"Generated Broker-Credential-JWT -> {OUTPUT_TOKEN_PATH}")
    print(f"  brokerName: {BROKER_NAME}")
    print(f"  brokerUrl:  {BROKER_URL}")
    print(f"  exp:        {claims['exp']} (in {TTL_SECONDS}s)")
    print(f"  size:       {len(token)} chars")
    print(f"  preview:    {token[:60]}...")


if __name__ == "__main__":
    main()
