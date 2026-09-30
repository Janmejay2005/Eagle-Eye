"""
Policy bundle schema and signing canonicalization for controlled self-healing.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from src.schemas import Policy
from src.self_healing.crypto_signing import verify_payload_signature


class PolicyBundle(BaseModel):
    """Cryptographically sealed rule bundle containing versioned policy updates."""
    bundle_id: str = Field(..., description="Unique bundle UUID")
    version: str = Field(..., description="Target policy version")
    previous_version: str = Field(..., description="Baseline version being updated")
    target_policy: Policy = Field(..., description="New policy specification")
    change_rationale: str = Field(..., description="Justification explaining incident response")
    incident_id: Optional[str] = Field(None, description="Linked incident triggering this update")
    created_at: float = Field(default_factory=lambda: time.time())
    shadow_test_passed: bool = Field(default=False)
    shadow_test_metrics: Dict[str, Any] = Field(default_factory=dict)
    admin_identity_id: Optional[str] = Field(None, description="Approving admin identifier")
    ed25519_signature: Optional[str] = Field(None, description="Base64 Ed25519 signature over canonical bundle payload")

    def canonical_bytes(self) -> bytes:
        """Serializes bundle fields (excluding signature) in deterministic sorted JSON format."""
        data = {
            "bundle_id": self.bundle_id,
            "version": self.version,
            "previous_version": self.previous_version,
            "target_policy": json.loads(self.target_policy.canonical_json()),
            "change_rationale": self.change_rationale,
            "incident_id": self.incident_id or "",
            "shadow_test_passed": self.shadow_test_passed,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def verify_signature(self, admin_public_key_b64: str) -> bool:
        if not self.ed25519_signature:
            return False
        return verify_payload_signature(admin_public_key_b64, self.canonical_bytes(), self.ed25519_signature)
