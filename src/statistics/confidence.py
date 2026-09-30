"""
Finite-sample confidence intervals and quantum security statistical bounds.
No AI/ML — analytical statistical bounds.
"""
from __future__ import annotations

import math
from typing import Tuple
from scipy import stats


def wilson_score_interval(successes: int, trials: int, confidence: float = 0.95) -> Tuple[float, float]:
    """
    Computes Wilson score confidence interval for binomial proportion.
    Robust for small to moderate trials and proportions close to 0 or 1.
    """
    if trials == 0:
        return 0.0, 1.0

    p_hat = successes / trials
    # Normal quantile z for given two-sided confidence
    alpha = 1.0 - confidence
    z = float(stats.norm.ppf(1.0 - alpha / 2.0))

    z2 = z * z
    denom = 1.0 + z2 / trials
    center = (p_hat + z2 / (2.0 * trials)) / denom
    half_width = (z * math.sqrt((p_hat * (1.0 - p_hat) / trials) + (z2 / (4.0 * trials * trials)))) / denom

    lower = max(0.0, center - half_width)
    upper = min(1.0, center + half_width)
    if successes == 0 or lower < 1e-15:
        lower = 0.0
    if successes == trials or (1.0 - upper) < 1e-15:
        upper = 1.0
    return float(lower), float(upper)


def clopper_pearson_interval(successes: int, trials: int, confidence: float = 0.95) -> Tuple[float, float]:
    """
    Computes Clopper-Pearson exact confidence interval using beta distributions.
    Guarantees coverage probability >= confidence.
    """
    if trials == 0:
        return 0.0, 1.0

    alpha = 1.0 - confidence
    lower = 0.0 if successes == 0 else float(stats.beta.ppf(alpha / 2.0, successes, trials - successes + 1))
    upper = 1.0 if successes == trials else float(stats.beta.ppf(1.0 - alpha / 2.0, successes + 1, trials - successes))
    return lower, upper


def hoeffding_upper_bound(successes: int, trials: int, confidence: float = 0.95) -> float:
    """
    Computes Hoeffding upper bound on true error rate:
    P(p > p_hat + epsilon) <= exp(-2 * trials * epsilon^2) = 1 - confidence.
    """
    if trials == 0:
        return 1.0
    p_hat = successes / trials
    epsilon = math.sqrt(-math.log(1.0 - confidence) / (2.0 * trials))
    return float(min(1.0, p_hat + epsilon))
