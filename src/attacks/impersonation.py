"""
Impersonation attack simulations: unregistered signers, revoked identities, and context spoofing.
"""
from __future__ import annotations

from src.schemas import Signature


class ImpersonationSimulator:
    """Generates parameterized impersonation attack vectors."""

    @staticmethod
    def spoof_unregistered_signer(
        valid_signature: Signature,
        attacker_id: str = "eve@malicious-node.org",
    ) -> Signature:
        """Adversary Eve claims to be the sender using an unregistered identity."""
        tampered = valid_signature.model_copy(deep=True)
        tampered.signer_identity = attacker_id
        return tampered

    @staticmethod
    def spoof_role_mismatch(
        valid_signature: Signature,
        verifier_identity_id: str,
    ) -> Signature:
        """Adversary signs with an identity that has only VERIFIER permissions, not SIGNER permissions."""
        tampered = valid_signature.model_copy(deep=True)
        tampered.signer_identity = verifier_identity_id
        return tampered
