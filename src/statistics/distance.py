"""
Distribution distances: Total Variation Distance (TVD), Hellinger distance, and Bhattacharyya coefficient.
No AI/ML — analytical probability distribution metrics.
"""
from __future__ import annotations

import math
from typing import Dict, List, Tuple
import numpy as np

from src.schemas.measurement import MeasurementBatch


def total_variation_distance(p: Tuple[float, float], q: Tuple[float, float]) -> float:
    """
    Total Variation Distance (TVD) between two discrete binary distributions:
    TVD(P, Q) = 0.5 * (|p0 - q0| + |p1 - q1|)
    """
    return float(0.5 * (abs(p[0] - q[0]) + abs(p[1] - q[1])))


def hellinger_distance(p: Tuple[float, float], q: Tuple[float, float]) -> float:
    """
    Hellinger distance H(P, Q) in [0, 1]:
    H(P, Q) = sqrt(1 - sum(sqrt(p_i * q_i)))
    """
    bc = math.sqrt(max(0.0, p[0] * q[0])) + math.sqrt(max(0.0, p[1] * q[1]))
    bc = min(1.0, bc)
    return float(math.sqrt(max(0.0, 1.0 - bc)))


def compute_batch_tvd(batch: MeasurementBatch) -> float:
    """
    Computes average TVD between observed shot frequencies and expected ideal distribution.
    For ideal_outcome 0, ideal distribution is (1.0, 0.0). For 1, (0.0, 1.0).
    """
    evaluated = 0
    tvd_sum = 0.0

    for rec in batch.records:
        if rec.ideal_outcome is not None and rec.shots > 0:
            evaluated += 1
            observed_p0 = rec.counts.get("0", 0) / rec.shots
            observed_p1 = rec.counts.get("1", 0) / rec.shots
            ideal_p0 = 1.0 if rec.ideal_outcome == 0 else 0.0
            ideal_p1 = 1.0 if rec.ideal_outcome == 1 else 0.0

            tvd = total_variation_distance((observed_p0, observed_p1), (ideal_p0, ideal_p1))
            tvd_sum += tvd

    return float(tvd_sum / evaluated) if evaluated > 0 else 0.0
