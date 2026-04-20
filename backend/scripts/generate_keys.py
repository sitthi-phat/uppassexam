"""
Generate RSA key pair for local development.

Usage:
  python scripts/generate_keys.py

Outputs:
  keys/private_v1.pem  — Keep secret; mount as Docker secret in production
  keys/public_v1.pem   — Share with the frontend library
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair(version: str = "v1", key_size: int = 2048) -> None:
    os.makedirs("keys", exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    priv_path = f"keys/private_{version}.pem"
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    os.chmod(priv_path, 0o600)   # owner read-only

    pub_path = f"keys/public_{version}.pem"
    with open(pub_path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    print(f"Generated RSA-{key_size} key pair  version={version}")
    print(f"  Private: {priv_path}  (KEEP SECRET)")
    print(f"  Public:  {pub_path}   (share with frontend)")


if __name__ == "__main__":
    generate_rsa_keypair("v1")
