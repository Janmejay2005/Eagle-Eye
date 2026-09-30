"""
Statistics package for quantum metrics, confidence bounds, distances, and sequential tests.
Zero AI/ML.
"""
from src.statistics.qber import calculate_qber, QBERReport
from src.statistics.confidence import (
    wilson_score_interval,
    clopper_pearson_interval,
    hoeffding_upper_bound,
)
from src.statistics.distance import (
    total_variation_distance,
    hellinger_distance,
    compute_batch_tvd,
)
from src.statistics.sequential import (
    SequentialProbabilityRatioTest,
    SPRTResult,
)
from src.statistics.evaluator import (
    StatisticalEvaluator,
    QuantumStatisticalSummary,
)

__all__ = [
    "calculate_qber",
    "QBERReport",
    "wilson_score_interval",
    "clopper_pearson_interval",
    "hoeffding_upper_bound",
    "total_variation_distance",
    "hellinger_distance",
    "compute_batch_tvd",
    "SequentialProbabilityRatioTest",
    "SPRTResult",
    "StatisticalEvaluator",
    "QuantumStatisticalSummary",
]
