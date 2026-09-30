"""
Controlled self-healing package for signed policy bundles, shadow testing, and reversible rollbacks.
"""
from src.self_healing.crypto_signing import (
    generate_ed25519_keypair,
    sign_payload,
    verify_payload_signature,
)
from src.self_healing.bundle import PolicyBundle
from src.self_healing.shadow import ShadowTestRunner
from src.self_healing.engine import (
    SelfHealingEngine,
    UnapprovedUpdateError,
    ShadowRegressionError,
)

__all__ = [
    "generate_ed25519_keypair",
    "sign_payload",
    "verify_payload_signature",
    "PolicyBundle",
    "ShadowTestRunner",
    "SelfHealingEngine",
    "UnapprovedUpdateError",
    "ShadowRegressionError",
]
