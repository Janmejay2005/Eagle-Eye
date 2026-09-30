"""
Signature schema encapsulating teleportation metadata, Pauli corrections, and canonical binding.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import List, Optional
from pydantic import BaseModel, Field

from src.schemas.measurement import MeasurementBatch


def compute_canonical_binding(
    signer_key: str,
    message_digest: str,
    session_id: str,
    nonce: str,
    timestamp: float,
    pauli_corrections: List[str]
) -> str:
    """HMAC-SHA256 canonical binding of classical message and quantum teleportation metadata."""
    payload = f"{message_digest}:{session_id}:{nonce}:{timestamp:.6f}:{','.join(pauli_corrections)}".encode("utf-8")
    return hmac.new(signer_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()


class Signature(BaseModel):
    """Quantum digital signature packet holding teleportation and binding proofs."""
    signature_id: str = Field(..., description="Unique signature packet UUID")
    message_id: str = Field(..., description="Target message UUID")
    signer_identity: str = Field(..., description="Claimed signer identity ID")
    session_id: str = Field(..., description="Freshness session ID")
    nonce: str = Field(..., min_length=8, description="Cryptographic nonce to guarantee anti-replay")
    timestamp: float = Field(..., description="Creation epoch timestamp")
    qubit_count: int = Field(..., gt=0, description="Number of qubits in signature sequence")
    pauli_corrections: List[str] = Field(..., min_length=1, description="List of Pauli correction ops ('I','X','Z','XZ')")
    basis_announcements: List[str] = Field(..., min_length=1, description="Basis announcements for verification checks")
    canonical_binding: str = Field(..., description="Cryptographic binding digest of message and quantum metadata")
    measurements: Optional[MeasurementBatch] = Field(None, description="Observed verifier measurement batch")

    def verify_binding(self, signer_key: str, message_digest: str) -> bool:
        expected = compute_canonical_binding(
            signer_key=signer_key,
            message_digest=message_digest,
            session_id=self.session_id,
            nonce=self.nonce,
            timestamp=self.timestamp,
            pauli_corrections=self.pauli_corrections
        )
        return hmac.compare_digest(self.canonical_binding, expected)
