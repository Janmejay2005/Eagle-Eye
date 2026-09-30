"""
Deterministic and explainable verification engine evaluating QDS requests to ACCEPT, REJECT, or ESCALATE.
"""
from __future__ import annotations

import time
import uuid
from typing import Optional, Tuple

from src.schemas import (
    Message,
    Signature,
    Policy,
    Decision,
    Verdict,
    Incident,
    AttackType,
    IncidentSeverity,
)
from src.guards import (
    CanonicalBindingGuard,
    IdentityGuard,
    IdentityRegistry,
    FreshnessGuard,
    RateLimiter,
)
from src.statistics import StatisticalEvaluator
from src.decision.audit_ledger import AuditLedger


class VerificationEngine:
    """Core verifier service implementing fail-closed security and explainable verdicts."""

    def __init__(
        self,
        registry: IdentityRegistry,
        freshness_guard: Optional[FreshnessGuard] = None,
        rate_limiter: Optional[RateLimiter] = None,
        audit_ledger: Optional[AuditLedger] = None,
        evaluator: Optional[StatisticalEvaluator] = None,
    ):
        self.registry = registry
        self.identity_guard = IdentityGuard(registry)
        self.freshness_guard = freshness_guard or FreshnessGuard()
        self.rate_limiter = rate_limiter or RateLimiter(window_seconds=60.0)
        self.audit_ledger = audit_ledger or AuditLedger()
        self.evaluator = evaluator or StatisticalEvaluator()

    def verify(
        self,
        message: Message,
        signature: Signature,
        verifier_identity_id: str,
        policy: Policy,
        current_time: Optional[float] = None,
    ) -> Decision:
        """
        Executes end-to-end deterministic verification:
        1. Verifier authorization & rate limiting.
        2. Signer identity & context authorization.
        3. Message digest integrity.
        4. Freshness, session validity & anti-replay.
        5. Classical & quantum canonical binding.
        6. Quantum projective measurement statistics (QBER, TVD, Wilson CI, SPRT).
        7. Decision emission and cryptographic hash-chain sealing.
        """
        now = time.time() if current_time is None else current_time
        decision_id = f"dec-{uuid.uuid4().hex[:12]}"
        request_id = f"req-{uuid.uuid4().hex[:8]}"

        failed_checks = []
        reasons = []
        stats_dict = {}

        # 1. Verifier authorization
        ok_v, reason_v = self.identity_guard.verify_verifier(verifier_identity_id)
        if not ok_v:
            failed_checks.append("VERIFIER_AUTHORIZATION")
            reasons.append(reason_v)
            return self._finalize_decision(
                decision_id, request_id, signature, message, Verdict.REJECT, reasons, failed_checks, stats_dict, policy.version, now
            )

        # Rate limiting on verifier node
        allowed_rate, _ = self.rate_limiter.is_allowed(verifier_identity_id, limit=policy.rate_limit_per_minute, current_time=now)
        if not allowed_rate:
            failed_checks.append("RATE_LIMIT")
            reasons.append(f"RATE_LIMIT_EXCEEDED: Exceeded {policy.rate_limit_per_minute} verifications/min.")
            return self._finalize_decision(
                decision_id, request_id, signature, message, Verdict.REJECT, reasons, failed_checks, stats_dict, policy.version, now
            )

        # 2. Signer authorization
        ok_s, reason_s = self.identity_guard.verify_signer(signature.signer_identity)
        if not ok_s:
            failed_checks.append("SIGNER_IDENTITY")
            reasons.append(reason_s)

        # 3. Message integrity
        ok_m, reason_m = CanonicalBindingGuard.verify_message_integrity(message)
        if not ok_m:
            failed_checks.append("MESSAGE_INTEGRITY")
            reasons.append(reason_m)

        # 4. Freshness and anti-replay
        ok_f, reason_f, replay_evidence = self.freshness_guard.check_freshness_and_replay(signature, policy, current_time=now)
        if not ok_f:
            failed_checks.append("FRESHNESS_OR_REPLAY")
            reasons.append(reason_f)
            if replay_evidence:
                stats_dict["replay_evidence"] = replay_evidence

        # 5. Canonical binding verification
        signer_key = self.registry.get_secret_key(signature.signer_identity) or ""
        ok_b, reason_b = CanonicalBindingGuard.verify_signature_binding(signature, message, signer_key)
        if not ok_b:
            failed_checks.append("CANONICAL_BINDING")
            reasons.append(reason_b)

        # If any pre-flight security guard failed, fail closed immediately
        if failed_checks:
            return self._finalize_decision(
                decision_id, request_id, signature, message, Verdict.REJECT, reasons, failed_checks, stats_dict, policy.version, now
            )

        # 6. Quantum measurement evaluation
        if signature.measurements is None or signature.measurements.sample_size < policy.min_qubit_sample_size:
            failed_checks.append("INSUFFICIENT_SAMPLE_SIZE")
            reasons.append(
                f"INSUFFICIENT_SAMPLES: Expected >= {policy.min_qubit_sample_size} qubits, got "
                f"{signature.measurements.sample_size if signature.measurements else 0}."
            )
            return self._finalize_decision(
                decision_id, request_id, signature, message, Verdict.REJECT, reasons, failed_checks, stats_dict, policy.version, now
            )

        q_summary = self.evaluator.evaluate_batch(signature.measurements, policy)
        stats_dict = q_summary.model_dump()

        # Decision threshold evaluation
        if q_summary.exceeds_hard_qber or q_summary.exceeds_tvd or q_summary.sprt_verdict == "ATTACK":
            verdict = Verdict.REJECT
            failed_checks.append("QUANTUM_SECURITY_BOUNDS_EXCEEDED")
            reasons.append(
                f"ANOMALOUS_QUANTUM_METRICS: Observed QBER {q_summary.qber:.4f} (max {policy.max_qber_threshold}), "
                f"TVD {q_summary.mean_tvd:.4f} (max {policy.max_tvd_threshold}), SPRT: {q_summary.sprt_verdict}."
            )
            # Quarantine the affected session to prevent further channel compromise
            self.freshness_guard.quarantine_session(signature.session_id)
        elif q_summary.exceeds_escalate_qber:
            if policy.allow_escalate_on_honest_noise:
                verdict = Verdict.ESCALATE
                reasons.append(
                    f"ELEVATED_CHANNEL_NOISE_CONTROLLED_ESCALATE: QBER {q_summary.qber:.4f} between soft threshold "
                    f"({policy.escalate_qber_threshold}) and hard threshold ({policy.max_qber_threshold})."
                )
            else:
                verdict = Verdict.REJECT
                failed_checks.append("EXCEEDED_ESCALATE_QBER_REJECT")
                reasons.append(f"QBER {q_summary.qber:.4f} exceeded soft threshold and policy rejects escalation.")
        else:
            verdict = Verdict.ACCEPT
            reasons.append("SIGNATURE_AND_QUANTUM_METRICS_VERIFIED_SUCCESSFULLY")

        return self._finalize_decision(
            decision_id, request_id, signature, message, verdict, reasons, failed_checks, stats_dict, policy.version, now
        )

    def _finalize_decision(
        self,
        decision_id: str,
        request_id: str,
        signature: Signature,
        message: Message,
        verdict: Verdict,
        reasons: list,
        failed_checks: list,
        stats_dict: dict,
        policy_version: str,
        timestamp: float,
    ) -> Decision:
        decision = Decision(
            decision_id=decision_id,
            request_id=request_id,
            signature_id=signature.signature_id,
            message_id=message.message_id,
            verdict=verdict,
            reasons=reasons,
            failed_checks=failed_checks,
            statistics=stats_dict,
            policy_version=policy_version,
            timestamp=timestamp,
        )
        # Seal and append to hash-chain audit ledger
        return self.audit_ledger.append_decision(decision)
