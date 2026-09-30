"""
Identity and role schema for participants in the QDS network.
"""
from __future__ import annotations

from enum import Enum
from typing import List
from pydantic import BaseModel, Field


class IdentityRole(str, Enum):
    SIGNER = "SIGNER"
    VERIFIER = "VERIFIER"
    AUDITOR = "AUDITOR"
    ADMIN = "ADMIN"


class Identity(BaseModel):
    """Cryptographic identity record for signers, verifiers, and auditors."""
    identity_id: str = Field(..., description="Unique identity identifier")
    name: str = Field(..., description="Human-readable identity name")
    role: IdentityRole = Field(..., description="Network role")
    public_key_hex: str = Field(..., description="Public key representation in hex")
    is_authorized: bool = Field(default=True, description="Whether identity is actively trusted")
    permissions: List[str] = Field(default_factory=list, description="Explicit permitted actions")

    def has_permission(self, action: str) -> bool:
        return self.is_authorized and action in self.permissions
