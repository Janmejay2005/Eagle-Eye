"""
Unit tests for deterministic quantum statistics (QBER, Wilson CI, TVD, SPRT).
Acceptance Gate 4: Honest and attack corpus results reproducible; no AI/ML.
"""
import numpy as np
import pytest

from src.schemas import MeasurementBatch, MeasurementRecord, PauliBasis, Policy
from src.statistics import (
    calculate_qber,
    wilson_score_interval,
    clopper_pearson_interval,
    hoeffding_upper_bound,
    total_variation_distance,
    hellinger_distance,
    compute_batch_tvd,
    SequentialProbabilityRatioTest,
    StatisticalEvaluator,
)


def test_qber_and_basis_breakdown():
    """QBER and basis-specific error rates are calculated deterministically."""
    records = [
        # Basis X: 2 trials, 0 error
        MeasurementRecord(qubit_index=0, basis=PauliBasis.X, outcome=0, ideal_outcome=0),
        MeasurementRecord(qubit_index=1, basis=PauliBasis.X, outcome=1, ideal_outcome=1),
        # Basis Z: 2 trials, 1 error
        MeasurementRecord(qubit_index=2, basis=PauliBasis.Z, outcome=1, ideal_outcome=0),
        MeasurementRecord(qubit_index=3, basis=PauliBasis.Z, outcome=1, ideal_outcome=1),
    ]
    batch = MeasurementBatch(batch_id="b1", session_id="s1", records=records)

    report = calculate_qber(batch)
    assert report.total_qubits == 4
    assert report.evaluated_qubits == 4
    assert report.error_count == 1
    assert np.isclose(report.overall_qber, 0.25)
    assert np.isclose(report.basis_qber["X"], 0.0)
    assert np.isclose(report.basis_qber["Z"], 0.5)
    assert np.isclose(report.basis_asymmetry, 0.5)


def test_wilson_confidence_intervals():
    """Wilson interval contains sample proportion and respects mathematical bounds [0, 1]."""
    low, high = wilson_score_interval(successes=5, trials=100, confidence=0.95)
    assert 0.0 <= low <= 0.05 <= high <= 1.0

    # Edge cases: 0 errors
    low_zero, high_zero = wilson_score_interval(successes=0, trials=50, confidence=0.95)
    assert low_zero == 0.0
    assert high_zero > 0.0

    # Compare with Clopper-Pearson
    cp_low, cp_high = clopper_pearson_interval(successes=5, trials=100, confidence=0.95)
    assert cp_low <= 0.05 <= cp_high

    # Hoeffding bound
    h_up = hoeffding_upper_bound(successes=5, trials=100, confidence=0.95)
    assert h_up >= 0.05


def test_distance_metrics():
    """TVD and Hellinger distance satisfy metric properties."""
    p_same = (0.7, 0.3)
    assert total_variation_distance(p_same, p_same) == 0.0
    assert hellinger_distance(p_same, p_same) == 0.0

    p_ortho1 = (1.0, 0.0)
    p_ortho2 = (0.0, 1.0)
    assert np.isclose(total_variation_distance(p_ortho1, p_ortho2), 1.0)
    assert np.isclose(hellinger_distance(p_ortho1, p_ortho2), 1.0)


def test_sprt_honest_vs_attack():
    """Wald's SPRT discriminates between honest noise and attack sequence without AI."""
    sprt = SequentialProbabilityRatioTest(p0=0.03, p1=0.15, alpha=0.01, beta=0.01)

    # Honest sequence: 98 successes, 2 errors (2% error rate < p0=0.03)
    honest_seq = [False] * 49 + [True] + [False] * 49 + [True]
    res_honest = sprt.evaluate(honest_seq)
    assert res_honest.verdict == "HONEST"

    # Attack sequence: 10 errors out of 30 samples (33.3% error rate > p1=0.15)
    attack_seq = [True, False, True, False, True, True, False, True, False, True] * 3
    res_attack = sprt.evaluate(attack_seq)
    assert res_attack.verdict == "ATTACK"


def test_evaluator_honest_corpus_reproducibility():
    """Evaluator on honest batch yields ACCEPT metrics with no threshold violations."""
    policy = Policy(max_qber_threshold=0.08, escalate_qber_threshold=0.045, max_tvd_threshold=0.15)
    evaluator = StatisticalEvaluator()

    # Create honest batch with ~2% noise
    records = []
    for i in range(100):
        is_err = (i in (12, 64))  # 2 errors out of 100
        outcome = 1 if is_err else 0
        records.append(
            MeasurementRecord(
                qubit_index=i,
                basis=PauliBasis.Z,
                outcome=outcome,
                ideal_outcome=0,
                shots=1000,
                counts={"0": 980 if not is_err else 20, "1": 20 if not is_err else 980},
            )
        )
    batch = MeasurementBatch(batch_id="b-honest", session_id="s1", records=records)

    summary = evaluator.evaluate_batch(batch, policy)
    assert summary.qber == 0.02
    assert not summary.exceeds_hard_qber
    assert not summary.exceeds_escalate_qber
    assert summary.sprt_verdict == "HONEST"
