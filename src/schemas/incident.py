"""
Incident schema representing confirmed security alerts, attack evidence, and self-healing lifecycle.
"""
from __future__ import annotations

from enum import Enum
import time
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class AttackType(str, Enum):
    FORGERY = "FORGERY"
    IMPERSONATION = "IMPERSONATION"
    REPLAY = "REPLAY"
    CHANNEL_MANIPULATION = "CHANNEL_MANIPULATION"
    UNAUTHORIZED_VERIFICATION = "UNAUTHORIZED_VERIFICATION"
    POLICY_TAMPERING = "POLICY_TAMPERING"


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    DETECTED = "DETECTED"
    CONFIRMED = "CONFIRMED"
    RULE_PROPOSED = "RULE_PROPOSED"
    SHADOW_TESTED = "SHADOW_TESTED"
    APPROVED = "APPROVED"
    APPLIED = "APPLIED"
    ROLLED_BACK = "ROLLED_BACK"


class Incident(BaseModel):
    """Incident record capturing threat evidence and managing self-healing progression."""
    incident_id: str = Field(..., description="Unique incident identifier")
    timestamp: float = Field(default_factory=lambda: time.time(), description="Incident epoch")
    attack_type: AttackType = Field(..., description="Classified attack category")
    severity: IncidentSeverity = Field(..., description="Assessed impact severity")
    status: IncidentStatus = Field(default=IncidentStatus.DETECTED, description="Current workflow state")
    decision_id: str = Field(..., description="Associated decision record UUID")
    session_id: Optional[str] = Field(None, description="Affected session identifier")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Captured evidence and statistical telemetry")
    proposed_policy_delta: Optional[Dict[str, Any]] = Field(None, description="Proposed policy amendment")
    approval_signature: Optional[str] = Field(None, description="Cryptographic signature of administrator approving change")
    approver_id: Optional[str] = Field(None, description="Identity of approving administrator")
    shadow_test_passed: Optional[bool] = Field(None, description="Whether rule passed non-regression shadow testing")
    rollback_checkpoint_hash: Optional[str] = Field(None, description="Hash of the pre-incident policy checkpoint")
