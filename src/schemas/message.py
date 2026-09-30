"""
Message schema for QDS payload transmission.
"""
from __future__ import annotations

import hashlib
import time
from typing import Optional
from pydantic import BaseModel, Field, field_validator


def compute_message_digest(sender_id: str, receiver_id: str, timestamp: float, payload: str) -> str:
    """Computes deterministic SHA-256 digest of canonical message representation."""
    canonical_repr = f"{sender_id}:{receiver_id}:{timestamp:.6f}:{payload}".encode("utf-8")
    return hashlib.sha256(canonical_repr).hexdigest()


class Message(BaseModel):
    """Canonical message object to be signed and verified."""
    message_id: str = Field(..., description="Unique message UUID")
    payload: str = Field(..., description="Message content string or serialized data")
    sender_id: str = Field(..., description="Signer identity identifier (e.g., Alice)")
    receiver_id: str = Field(..., description="Intended receiver identifier (e.g., Bob)")
    timestamp: float = Field(default_factory=lambda: time.time(), description="Creation epoch timestamp")
    digest: str = Field(..., description="Deterministic SHA-256 digest of canonical message")

    @classmethod
    def create(cls, message_id: str, payload: str, sender_id: str, receiver_id: str, timestamp: Optional[float] = None) -> Message:
        ts = time.time() if timestamp is None else timestamp
        digest = compute_message_digest(sender_id, receiver_id, ts, payload)
        return cls(
            message_id=message_id,
            payload=payload,
            sender_id=sender_id,
            receiver_id=receiver_id,
            timestamp=ts,
            digest=digest,
        )

    def verify_integrity(self) -> bool:
        expected = compute_message_digest(self.sender_id, self.receiver_id, self.timestamp, self.payload)
        return self.digest == expected
