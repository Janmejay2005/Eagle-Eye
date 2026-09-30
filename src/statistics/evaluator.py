"""
Multi-statistic evaluation bundle for deterministic QDS threat detection.
No AI/ML — purely transparent, explainable quantum statistical methods.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.schemas.measurement import MeasurementBatch
from src.schemas.policy import Policy
from src.statistics.qber import calculate_qber, QBERReport
from src.statistics.confidence import wilson_score_interval, clopper_pearson_interval
from src.statistics.distance import compute_batch_tvd
from src.statistics.sequential import SequentialProbabilityRatioTest, SPRTResult


class QuantumStatisticalSummary(BaseModel):
    """Explainable quantum telemetry metrics comparing observed stats to policy bounds."""
    sample_size: int = Field(..., ge=0)
    error_count: int = Field(..., ge=0)
    qber: float = Field(..., ge=0.0, le=1.0)
    qber_ci_lower: float = Field(..., ge=0.0, le=1.0)
    qber_ci_upper: float = Field(..., ge=0.0, le=1.0)
    basis_qber: Dict[str, float] = Field(default_factory=dict)
    basis_asymmetry: float = Field(..., ge=0.0)
    mean_tvd: float = Field(..., ge=0.0, le=1.0)
    sprt_verdict: str = Field(...)
    sprt_llr: float = Field(...)
    exceeds_hard_qber: bool = Field(...)
    exceeds_escalate_qber: bool = Field(...)
    exceeds_tvd: bool = Field(...)


class StatisticalEvaluator:
    """Evaluates measurement batches against verification policies deterministically."""

    def __init__(self, sprt_tester: Optional[SequentialProbabilityRatioTest] = None):
        self.sprt_tester = sprt_tester or SequentialProbabilityRatioTest()

    def evaluate_batch(self, batch: MeasurementBatch, policy: Policy) -> QuantumStatisticalSummary:
        qber_rep = calculate_qber(batch)
        err_count = qber_rep.error_count
        eval_count = qber_rep.evaluated_qubits

        ci_low, ci_high = wilson_score_interval(
            successes=err_count,
            trials=eval_count,
            confidence=policy.confidence_level,
        )

        tvd = compute_batch_tvd(batch)

        # Build error sequence for SPRT
        err_seq = [
            (rec.outcome != rec.ideal_outcome)
            for rec in batch.records
            if rec.ideal_outcome is not None
        ]
        sprt_res = self.sprt_tester.evaluate(err_seq)

        exceeds_hard = qber_rep.overall_qber > policy.max_qber_threshold
        exceeds_escalate = qber_rep.overall_qber > policy.escalate_qber_threshold
        exceeds_tvd = tvd > policy.max_tvd_threshold

        return QuantumStatisticalSummary(
            sample_size=eval_count,
            error_count=err_count,
            qber=qber_rep.overall_qber,
            qber_ci_lower=ci_low,
            qber_ci_upper=ci_high,
            basis_qber=qber_rep.basis_qber,
            basis_asymmetry=qber_rep.basis_asymmetry,
            mean_tvd=tvd,
            sprt_verdict=sprt_res.verdict,
            sprt_llr=sprt_res.log_likelihood_ratio,
            exceeds_hard_qber=exceeds_hard,
            exceeds_escalate_qber=exceeds_escalate,
            exceeds_tvd=exceeds_tvd,
        )
