"""
Session schema for stateful replay protection, freshness, and channel quarantine.
"""
from __future__ import annotations

import time
from typing import List, Set
from pydantic import BaseModel, Field


class Session(BaseModel):
    """Session state maintained by verifiers for freshness and anti-replay protection."""
    session_id: str = Field(..., description="Unique session identifier")
    signer_id: str = Field(..., description="Authorized signer for session")
    verifier_id: str = Field(..., description="Designated verifier node ID")
    created_at: float = Field(default_factory=lambda: time.time(), description="Session start epoch")
    expires_at: float = Field(..., description="Session expiration epoch")
    seen_nonces: List[str] = Field(default_factory=list, description="Historical nonces observed in this session")
    is_active: bool = Field(default=True, description="Active status")
    is_quarantined: bool = Field(default=False, description="Whether channel has been quarantined due to disturbance")

    def is_expired(self, current_time: float) -> bool:
        return current_time > self.expires_at

    def register_nonce(self, nonce: str) -> bool:
        """Attempts to register nonce. Returns True if fresh, False if replay detected."""
        if nonce in self.seen_nonces:
            return False
        self.seen_nonces.append(nonce)
        return True
