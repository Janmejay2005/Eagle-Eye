"""
Acceptance test for Phase 9: Benchmark suite execution and target gates verification.
Acceptance Gate 9: Results reproducible and PPT claims measured.
"""
from src.benchmark.benchmark_runner import BenchmarkRunner


def test_benchmark_runner_target_gates():
    """Executes benchmark on 5 seeds for fast CI/CD validation and asserts all gates pass."""
    runner = BenchmarkRunner(seeds_count=5)
    results = runner.run_full_benchmark()

    tg = results["target_gate_status"]
    pm = results["primary_metrics"]

    assert tg["replay_rejection_target_100pct"] is True
    assert tg["honest_acceptance_target_gte_95pct"] is True
    assert tg["attack_detection_target_gte_90pct"] is True
    assert tg["far_target_lte_5pct"] is True
    assert tg["evidence_completeness_100pct"] is True
    assert tg["rollback_success_100pct"] is True

    # Performance targets
    assert results["performance"]["mean_latency_ms"] < 1000.0
