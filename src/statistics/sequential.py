"""
Sequential Probability Ratio Test (SPRT) / Wald's test for sequential hypothesis testing.
Distinguishes ordinary channel noise from statistically significant adversarial manipulation.
No AI/ML — analytical sequential hypothesis testing.
"""
from __future__ import annotations

import math
from typing import List, Optional, Tuple
from pydantic import BaseModel, Field


class SPRTResult(BaseModel):
    """Result of sequential probability ratio evaluation."""
    verdict: str = Field(..., description="'HONEST', 'ATTACK', or 'INCONCLUSIVE'")
    log_likelihood_ratio: float = Field(..., description="Cumulative log-likelihood ratio Lambda")
    upper_bound: float = Field(..., description="Decision boundary ln((1 - beta) / alpha)")
    lower_bound: float = Field(..., description="Decision boundary ln(beta / (1 - alpha))")
    evaluated_samples: int = Field(..., ge=0)
    error_count: int = Field(..., ge=0)


class SequentialProbabilityRatioTest:
    """
    Wald SPRT tester for distinguishing honest channel noise (H0: p <= p0)
    from adversarial manipulation (H1: p >= p1).
    """

    def __init__(
        self,
        p0: float = 0.03,  # Honest noise baseline
        p1: float = 0.12,  # Adversarial disruption baseline
        alpha: float = 0.01,  # Type I error probability (false alarm)
        beta: float = 0.01,   # Type II error probability (missed detection)
    ):
        if not (0.0 < p0 < p1 < 1.0):
            raise ValueError(f"Must have 0 < p0 < p1 < 1, got p0={p0}, p1={p1}")
        self.p0 = p0
        self.p1 = p1
        self.alpha = alpha
        self.beta = beta

        self.lower_bound = math.log(beta / (1.0 - alpha))
        self.upper_bound = math.log((1.0 - beta) / alpha)

        self.log_llr_error = math.log(p1 / p0)
        self.log_llr_success = math.log((1.0 - p1) / (1.0 - p0))

    def evaluate(self, errors_sequence: List[bool]) -> SPRTResult:
        """Evaluates a sequence of boolean indicators (True if error, False otherwise)."""
        llr = 0.0
        error_cnt = 0

        for is_err in errors_sequence:
            if is_err:
                llr += self.log_llr_error
                error_cnt += 1
            else:
                llr += self.log_llr_success

        if llr >= self.upper_bound:
            verdict = "ATTACK"
        elif llr <= self.lower_bound:
            verdict = "HONEST"
        else:
            verdict = "INCONCLUSIVE"

        return SPRTResult(
            verdict=verdict,
            log_likelihood_ratio=llr,
            upper_bound=self.upper_bound,
            lower_bound=self.lower_bound,
            evaluated_samples=len(errors_sequence),
            error_count=error_cnt,
        )
