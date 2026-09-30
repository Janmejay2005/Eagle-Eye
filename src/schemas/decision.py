"""
Decision schema representing deterministic, explainable verification verdicts and audit events.
"""
from __future__ import annotations

from enum import Enum
import hashlib
import json
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Verdict(str, Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    ESCALATE = "ESCALATE"


class Decision(BaseModel):
    """Deterministic, explainable verification decision record with tamper-evident audit linkage."""
    decision_id: str = Field(..., description="Unique decision UUID")
    request_id: str = Field(..., description="Correlated verification request ID")
    signature_id: str = Field(..., description="Target signature packet ID")
    message_id: str = Field(..., description="Target message ID")
    verdict: Verdict = Field(..., description="Final verification verdict (ACCEPT, REJECT, ESCALATE)")
    reasons: List[str] = Field(..., description="Human-readable and structured reason codes")
    failed_checks: List[str] = Field(default_factory=list, description="List of failed rule/statistical checks")
    statistics: Dict[str, Any] = Field(default_factory=dict, description="Observed statistical metrics and intervals")
    policy_version: str = Field(..., description="Active policy version used for evaluation")
    timestamp: float = Field(default_factory=lambda: time.time(), description="Decision epoch timestamp")
    event_hash: Optional[str] = Field(None, description="SHA-256 hash of this decision block")
    previous_event_hash: Optional[str] = Field(None, description="Hash of preceding event for tamper-evident blockchain")

    def compute_hash(self) -> str:
        """Computes deterministic SHA-256 hash over canonical representation including previous hash."""
        data = {
            "decision_id": self.decision_id,
            "request_id": self.request_id,
            "signature_id": self.signature_id,
            "message_id": self.message_id,
            "verdict": self.verdict.value,
            "reasons": sorted(self.reasons),
            "failed_checks": sorted(self.failed_checks),
            "policy_version": self.policy_version,
            "timestamp": f"{self.timestamp:.6f}",
            "previous_event_hash": self.previous_event_hash or ""
        }
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def seal(self, previous_hash: Optional[str] = None) -> Decision:
        """Seals the decision by linking previous event hash and calculating current event hash."""
        self.previous_event_hash = previous_hash
        self.event_hash = self.compute_hash()
        return self
