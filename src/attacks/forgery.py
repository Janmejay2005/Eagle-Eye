"""
Forgery attack simulations: classical message payload tampering and quantum state manipulation.
"""
from __future__ import annotations

import copy
from typing import List, Optional
import numpy as np

from src.schemas import Message, Signature, MeasurementBatch, MeasurementRecord


class ForgerySimulator:
    """Generates parameterized forgery attempts against message bindings and quantum states."""

    @staticmethod
    def tamper_message_payload(original_message: Message, tampered_payload: str) -> Message:
        """
        Adversary modifies classical message payload while retaining original message_id and digest.
        """
        return Message(
            message_id=original_message.message_id,
            payload=tampered_payload,
            sender_id=original_message.sender_id,
            receiver_id=original_message.receiver_id,
            timestamp=original_message.timestamp,
            digest=original_message.digest,  # Old digest creates mismatch with new payload
        )

    @staticmethod
    def tamper_quantum_measurements(
        signature: Signature,
        flip_fraction: float = 0.35,
        seed: Optional[int] = None,
    ) -> Signature:
        """
        Adversary tampers with the quantum channel or measurement outcomes,
        flipping a fraction of bits to induce high QBER and distribution distortion.
        """
        if signature.measurements is None:
            return signature

        rng = np.random.default_rng(seed)
        tampered_sig = signature.model_copy(deep=True)
        records = tampered_sig.measurements.records

        qubit_indices = rng.choice(len(records), size=int(len(records) * flip_fraction), replace=False)

        for idx in qubit_indices:
            rec = records[idx]
            # Flip binary outcome
            rec.outcome = 1 - rec.outcome
            # Invert raw counts
            c0 = rec.counts.get("0", 0)
            c1 = rec.counts.get("1", 0)
            rec.counts = {"0": c1, "1": c0}

        return tampered_sig

    @staticmethod
    def generate_random_signature_forgery(
        message: Message,
        claimed_signer: str,
        session_id: str,
        qubit_count: int = 32,
    ) -> Signature:
        """
        Adversary constructs a completely fabricated signature packet without Alice's secret key.
        """
        return Signature(
            signature_id=f"sig-forged-{message.message_id[:6]}",
            message_id=message.message_id,
            signer_identity=claimed_signer,
            session_id=session_id,
            nonce="forged-nonce-12345678",
            timestamp=message.timestamp,
            qubit_count=qubit_count,
            pauli_corrections=["I"] * qubit_count,
            basis_announcements=["Z"] * qubit_count,
            canonical_binding="deadbeef" * 8,  # Bogus HMAC
        )
