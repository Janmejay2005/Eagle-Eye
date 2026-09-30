"""
Canonical payload binding guards for QDS messages and quantum metadata.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import List, Tuple

from src.schemas import Message, Signature, compute_canonical_binding


class CanonicalBindingGuard:
    """Verifies cryptographic binding between classical payload and quantum metadata."""

    @staticmethod
    def verify_message_integrity(message: Message) -> Tuple[bool, str]:
        """Validates that the message digest matches its payload and parameters."""
        if not message.verify_integrity():
            return False, "MESSAGE_DIGEST_MISMATCH: Message payload does not match canonical digest."
        return True, "MESSAGE_INTEGRITY_VALID"

    @staticmethod
    def verify_signature_binding(
        signature: Signature,
        message: Message,
        signer_secret_key: str,
    ) -> Tuple[bool, str]:
        """
        Validates that the signature canonical binding cryptographically seals:
        (message_digest, session_id, nonce, timestamp, pauli_corrections).
        """
        # First ensure target message matches signature's message_id
        if signature.message_id != message.message_id:
            return False, f"MESSAGE_ID_MISMATCH: Signature binds to {signature.message_id}, received {message.message_id}."

        # Verify message integrity before validating signature binding
        if not message.verify_integrity():
            return False, "CANONICAL_BINDING_MISMATCH: Message payload does not match canonical digest."

        # Verify HMAC-SHA256 canonical binding
        if not signature.verify_binding(signer_secret_key, message.digest):
            return False, "CANONICAL_BINDING_MISMATCH: Signature binding does not match message digest or quantum metadata."

        return True, "CANONICAL_BINDING_VALID"
