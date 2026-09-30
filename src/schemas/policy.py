"""
Policy schema defining verification thresholds, bounds, and cryptographic signing.
"""
from __future__ import annotations

import json
from typing import Optional
from pydantic import BaseModel, Field


class Policy(BaseModel):
    """Verification policy bundle containing thresholds and integrity signatures."""
    policy_id: str = Field(default="eagle-eye-default-policy", description="Policy identifier")
    version: str = Field(default="1.0.0", description="Semantic version string")
    max_qber_threshold: float = Field(default=0.08, ge=0.0, le=1.0, description="Hard QBER reject threshold")
    escalate_qber_threshold: float = Field(default=0.045, ge=0.0, le=1.0, description="Soft QBER threshold to trigger ESCALATE")
    max_tvd_threshold: float = Field(default=0.15, ge=0.0, le=1.0, description="Max Total Variation Distance threshold")
    confidence_level: float = Field(default=0.95, ge=0.5, lt=1.0, description="Statistical confidence level (e.g., Wilson interval)")
    max_clock_skew_seconds: float = Field(default=10.0, gt=0.0, description="Maximum permitted clock skew in seconds")
    min_qubit_sample_size: int = Field(default=16, gt=0, description="Minimum qubit sample size required for verification")
    rate_limit_per_minute: int = Field(default=120, gt=0, description="Max verification requests per minute per verifier")
    allow_escalate_on_honest_noise: bool = Field(default=True, description="Permit ESCALATE under marginal honest noise")
    ed25519_signature: Optional[str] = Field(None, description="Hex Ed25519 signature of the canonical policy JSON")
    signing_key_id: Optional[str] = Field(None, description="ID of administrator identity that signed this policy")

    def canonical_json(self) -> str:
        """Produces canonical sorted JSON without the signature field for hashing/signing."""
        data = self.model_dump(exclude={"ed25519_signature"})
        return json.dumps(data, sort_keys=True, separators=(",", ":"))
