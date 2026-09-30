"""
Ed25519 cryptographic signing and verification for self-healing policy bundles and admin authorization.
"""
from __future__ import annotations

import base64
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


def generate_ed25519_keypair() -> Tuple[str, str]:
    """Generates a new Ed25519 private and public key in base64 format."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_b64 = base64.b64encode(private_key.private_bytes_raw()).decode("utf-8")
    pub_b64 = base64.b64encode(public_key.public_bytes_raw()).decode("utf-8")
    return priv_b64, pub_b64


def sign_payload(private_key_b64: str, payload_bytes: bytes) -> str:
    """Signs bytes with Ed25519 private key, returning base64 signature."""
    raw_priv = base64.b64decode(private_key_b64)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_priv)
    signature = private_key.sign(payload_bytes)
    return base64.b64encode(signature).decode("utf-8")


def verify_payload_signature(public_key_b64: str, payload_bytes: bytes, signature_b64: str) -> bool:
    """Verifies base64 Ed25519 signature against payload bytes."""
    try:
        raw_pub = base64.b64decode(public_key_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(raw_pub)
        raw_sig = base64.b64decode(signature_b64)
        public_key.verify(raw_sig, payload_bytes)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False
