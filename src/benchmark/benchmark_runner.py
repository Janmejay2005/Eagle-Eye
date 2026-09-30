"""
Eagle-Eye Benchmark Runner (SIH PS 26141).
Executes reproducible evaluations across Corpora H, F, I, R, C, E across 30 independent seeds,
calculating FAR, FRR, per-class detection, latency, throughput, and baseline comparisons.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Tuple
import numpy as np

from src.schemas import (
    Message,
    Signature,
    Policy,
    Session,
    Identity,
    IdentityRole,
    Verdict,
)
from src.protocol import QDSSimulator, QuantumNoiseChannel
from src.guards import IdentityRegistry, FreshnessGuard
from src.decision.verifier import VerificationEngine
from src.attacks import (
    ForgerySimulator,
    ImpersonationSimulator,
    ReplaySimulator,
    ChannelAttackSimulator,
)
from src.self_healing import SelfHealingEngine, generate_ed25519_keypair


class BenchmarkRunner:
    """Orchestrates comprehensive benchmark measurements across evaluation corpora."""

    def __init__(self, seeds_count: int = 30):
        self.seeds_count = seeds_count
        self.policy = Policy(
            policy_id="benchmark-policy-v1",
            version="1.0.0",
            max_qber_threshold=0.08,
            escalate_qber_threshold=0.045,
            max_tvd_threshold=0.15,
            confidence_level=0.95,
            max_clock_skew_seconds=10.0,
            min_qubit_sample_size=16,
            rate_limit_per_minute=10000,  # disable throttling during throughput benchmark
        )

    def run_full_benchmark(self) -> Dict[str, Any]:
        """Runs the entire benchmark protocol across 30 seeds."""
        start_total = time.time()

        honest_total = 0
        honest_accepted = 0

        forgery_total = 0
        forgery_detected = 0

        impersonation_total = 0
        impersonation_detected = 0

        replay_total = 0
        replay_detected = 0

        channel_total = 0
        channel_detected = 0

        edge_total = 0
        edge_detected = 0

        # Baseline comparative counters
        b1_malicious_detected = 0
        b2_malicious_detected = 0
        eagle_eye_malicious_detected = 0
        total_malicious_tested = 0

        latencies = []
        evidence_complete_count = 0
        total_decisions_evaluated = 0

        for seed in range(100, 100 + self.seeds_count):
            registry = IdentityRegistry()
            alice = Identity(
                identity_id=f"alice-{seed}@qds.bank",
                name="Alice",
                role=IdentityRole.SIGNER,
                public_key_hex="a1b2c3d4",
                is_authorized=True,
                permissions=["sign"],
            )
            bob = Identity(
                identity_id=f"bob-{seed}@qds.bank",
                name="Bob",
                role=IdentityRole.VERIFIER,
                public_key_hex="e5f60718",
                is_authorized=True,
                permissions=["verify"],
            )
            registry.register(alice, secret_key="benchmark-secret-key")
            registry.register(bob)

            guard = FreshnessGuard()
            engine = VerificationEngine(registry=registry, freshness_guard=guard)
            sim = QDSSimulator(seed=seed)

            base_ts = 1727700000.0 + seed * 100
            session = Session(
                session_id=f"sess-bench-{seed}",
                signer_id=alice.identity_id,
                verifier_id=bob.identity_id,
                created_at=base_ts - 50,
                expires_at=base_ts + 7200,
            )
            guard.register_session(session)

            # 1. Corpus H: Honest signatures (ideal + honest noise ~2%)
            for h_idx in range(5):
                ts = base_ts + h_idx * 2
                msg = Message.create(f"msg-h-{seed}-{h_idx}", f"Honest test data {h_idx}", alice.identity_id, bob.identity_id, timestamp=ts)
                noise = QuantumNoiseChannel(depolarizing_rate=0.02, seed=seed * 10 + h_idx)
                sig, _ = sim.generate_honest_signature_and_measurements(
                    message=msg,
                    signer_key="benchmark-secret-key",
                    session_id=session.session_id,
                    nonce=f"nonce-h-{seed}-{h_idx}",
                    qubit_count=32,
                    noise_channel=noise,
                    timestamp=ts,
                )
                t0 = time.perf_counter()
                dec = engine.verify(msg, sig, bob.identity_id, self.policy, current_time=ts)
                latencies.append(time.perf_counter() - t0)

                total_decisions_evaluated += 1
                honest_total += 1
                if dec.verdict in (Verdict.ACCEPT, Verdict.ESCALATE):
                    honest_accepted += 1
                if dec.event_hash and dec.reasons:
                    evidence_complete_count += 1

            # 2. Corpus F: Forgery attempts
            for f_idx in range(4):
                ts = base_ts + 20 + f_idx * 2
                msg = Message.create(f"msg-f-{seed}-{f_idx}", f"Legit data {f_idx}", alice.identity_id, bob.identity_id, timestamp=ts)
                sig, _ = sim.generate_honest_signature_and_measurements(
                    message=msg,
                    signer_key="benchmark-secret-key",
                    session_id=session.session_id,
                    nonce=f"nonce-f-{seed}-{f_idx}",
                    qubit_count=32,
                    timestamp=ts,
                )
                if f_idx % 2 == 0:
                    # Message tampering
                    tampered_msg = ForgerySimulator.tamper_message_payload(msg, "Tampered payload")
                    target_sig = sig
                    target_m = tampered_msg
                else:
                    # Quantum state tampering
                    target_sig = ForgerySimulator.tamper_quantum_measurements(sig, flip_fraction=0.35, seed=seed * 20 + f_idx)
                    target_m = msg

                t0 = time.perf_counter()
                dec = engine.verify(target_m, target_sig, bob.identity_id, self.policy, current_time=ts)
                latencies.append(time.perf_counter() - t0)

                total_decisions_evaluated += 1
                forgery_total += 1
                total_malicious_tested += 1
                if dec.verdict == Verdict.REJECT:
                    forgery_detected += 1
                    eagle_eye_malicious_detected += 1
                if dec.event_hash and dec.reasons:
                    evidence_complete_count += 1

                # Baseline checks for forgery
                # Baseline 1 (Fixed QBER only): only detects if QBER > threshold
                qber = dec.statistics.get("qber", 0.0) if dec.statistics else 0.0
                if qber > self.policy.max_qber_threshold:
                    b1_malicious_detected += 1
                # Baseline 2 (QBER + TVD):
                tvd = dec.statistics.get("mean_tvd", 0.0) if dec.statistics else 0.0
                if qber > self.policy.max_qber_threshold or tvd > self.policy.max_tvd_threshold:
                    b2_malicious_detected += 1

            # 3. Corpus I: Impersonation attempts
            for i_idx in range(3):
                ts = base_ts + 40 + i_idx * 2
                msg = Message.create(f"msg-i-{seed}-{i_idx}", "Impersonation probe", "unregistered-eve", bob.identity_id, timestamp=ts)
                sig, _ = sim.generate_honest_signature_and_measurements(
                    message=msg,
                    signer_key="fake-key",
                    session_id=session.session_id,
                    nonce=f"nonce-i-{seed}-{i_idx}",
                    qubit_count=32,
                    timestamp=ts,
                )
                t0 = time.perf_counter()
                dec = engine.verify(msg, sig, bob.identity_id, self.policy, current_time=ts)
                latencies.append(time.perf_counter() - t0)

                total_decisions_evaluated += 1
                impersonation_total += 1
                total_malicious_tested += 1
                if dec.verdict == Verdict.REJECT:
                    impersonation_detected += 1
                    eagle_eye_malicious_detected += 1
                if dec.event_hash and dec.reasons:
                    evidence_complete_count += 1
                # Baselines (QBER only) do NOT check identity, so they fail to detect impersonation!

            # 4. Corpus R: Replay attempts
            for r_idx in range(4):
                ts = base_ts + 60 + r_idx * 2
                msg = Message.create(f"msg-r-{seed}-{r_idx}", "Voucher token", alice.identity_id, bob.identity_id, timestamp=ts)
                nonce_r = f"nonce-r-{seed}-{r_idx}"
                sig, _ = sim.generate_honest_signature_and_measurements(
                    message=msg,
                    signer_key="benchmark-secret-key",
                    session_id=session.session_id,
                    nonce=nonce_r,
                    qubit_count=32,
                    timestamp=ts,
                )
                # Legitimate original
                engine.verify(msg, sig, bob.identity_id, self.policy, current_time=ts)
                # Replay attack
                replayed_sig = ReplaySimulator.create_identical_replay(sig)
                t0 = time.perf_counter()
                dec = engine.verify(msg, replayed_sig, bob.identity_id, self.policy, current_time=ts + 0.5)
                latencies.append(time.perf_counter() - t0)

                total_decisions_evaluated += 1
                replay_total += 1
                total_malicious_tested += 1
                if dec.verdict == Verdict.REJECT:
                    replay_detected += 1
                    eagle_eye_malicious_detected += 1
                if dec.event_hash and dec.reasons:
                    evidence_complete_count += 1
                # Baselines with only QBER do NOT detect replays because quantum states are valid!

            # 5. Corpus C: Channel manipulation (intercept-resend)
            for c_idx in range(3):
                ts = base_ts + 80 + c_idx * 2
                msg = Message.create(f"msg-c-{seed}-{c_idx}", "Disturbed data", alice.identity_id, bob.identity_id, timestamp=ts)
                sig_c, _ = ChannelAttackSimulator.simulate_intercept_resend(
                    simulator=sim,
                    message=msg,
                    signer_key="benchmark-secret-key",
                    session_id=session.session_id,
                    nonce=f"nonce-c-{seed}-{c_idx}",
                    qubit_count=64,
                    seed=seed * 30 + c_idx,
                )
                t0 = time.perf_counter()
                dec = engine.verify(msg, sig_c, bob.identity_id, self.policy, current_time=ts)
                latencies.append(time.perf_counter() - t0)

                total_decisions_evaluated += 1
                channel_total += 1
                total_malicious_tested += 1
                if dec.verdict == Verdict.REJECT:
                    channel_detected += 1
                    eagle_eye_malicious_detected += 1
                if dec.event_hash and dec.reasons:
                    evidence_complete_count += 1

                # Check baselines
                qber = dec.statistics.get("qber", 0.0) if dec.statistics else 0.0
                tvd = dec.statistics.get("mean_tvd", 0.0) if dec.statistics else 0.0
                if qber > self.policy.max_qber_threshold:
                    b1_malicious_detected += 1
                if qber > self.policy.max_qber_threshold or tvd > self.policy.max_tvd_threshold:
                    b2_malicious_detected += 1

            # 6. Corpus E: Edge cases (stale timestamp & small sample)
            for e_idx in range(2):
                ts = base_ts + 90 + e_idx * 2
                msg = Message.create(f"msg-e-{seed}-{e_idx}", "Edge test", alice.identity_id, bob.identity_id, timestamp=ts)
                sig_e, _ = sim.generate_honest_signature_and_measurements(
                    message=msg,
                    signer_key="benchmark-secret-key",
                    session_id=session.session_id,
                    nonce=f"nonce-e-{seed}-{e_idx}",
                    qubit_count=32,
                    timestamp=ts - 200,  # Stale timestamp
                )
                t0 = time.perf_counter()
                dec = engine.verify(msg, sig_e, bob.identity_id, self.policy, current_time=ts)
                latencies.append(time.perf_counter() - t0)

                total_decisions_evaluated += 1
                edge_total += 1
                total_malicious_tested += 1
                if dec.verdict == Verdict.REJECT:
                    edge_detected += 1
                    eagle_eye_malicious_detected += 1
                if dec.event_hash and dec.reasons:
                    evidence_complete_count += 1

        total_duration = time.time() - start_total

        # Rollback resilience benchmark (10 iterations)
        rollback_successes = 0
        rollback_trials = 10
        _, pub = generate_ed25519_keypair()
        priv, pub = generate_ed25519_keypair()
        admin = Identity(
            identity_id="adm@bench",
            name="Admin",
            role=IdentityRole.ADMIN,
            public_key_hex=pub,
            is_authorized=True,
            permissions=["admin"],
        )
        for _ in range(rollback_trials):
            sh_engine = SelfHealingEngine(self.policy)
            candidate = self.policy.model_copy()
            candidate.version = "1.0.1"
            bundle = sh_engine.propose_update(candidate, "Calibrate")
            sh_engine.run_shadow_tests(bundle.bundle_id)
            sh_engine.approve_and_sign(bundle.bundle_id, admin, priv)
            ckpt = sh_engine.apply_update(bundle.bundle_id, pub)
            restored = sh_engine.rollback(ckpt)
            if restored.version == "1.0.0":
                rollback_successes += 1

        # Calculate final benchmark metrics
        honest_acc_rate = honest_accepted / honest_total if honest_total else 0.0
        frr = (honest_total - honest_accepted) / honest_total if honest_total else 0.0

        forgery_det_rate = forgery_detected / forgery_total if forgery_total else 0.0
        impersonation_det_rate = impersonation_detected / impersonation_total if impersonation_total else 0.0
        replay_det_rate = replay_detected / replay_total if replay_total else 0.0
        channel_det_rate = channel_detected / channel_total if channel_total else 0.0
        edge_det_rate = edge_detected / edge_total if edge_total else 0.0

        total_malicious_detected = eagle_eye_malicious_detected
        far = (total_malicious_tested - total_malicious_detected) / total_malicious_tested if total_malicious_tested else 0.0
        overall_detection_rate = total_malicious_detected / total_malicious_tested if total_malicious_tested else 0.0

        evidence_completeness = evidence_complete_count / total_decisions_evaluated if total_decisions_evaluated else 0.0
        rollback_success_rate = rollback_successes / rollback_trials

        mean_latency = float(np.mean(latencies))
        p95_latency = float(np.percentile(latencies, 95))
        throughput = float(len(latencies) / total_duration)

        results = {
            "meta": {
                "evaluation_date": "2026-09-30",
                "seeds_evaluated": self.seeds_count,
                "total_decisions_evaluated": total_decisions_evaluated,
                "total_duration_seconds": round(total_duration, 2),
                "policy_version": self.policy.version,
            },
            "primary_metrics": {
                "honest_acceptance_rate": round(honest_acc_rate, 4),
                "frr_false_rejection_rate": round(frr, 4),
                "overall_attack_detection_rate": round(overall_detection_rate, 4),
                "far_false_acceptance_rate": round(far, 4),
                "replay_rejection_rate": round(replay_det_rate, 4),
                "evidence_completeness": round(evidence_completeness, 4),
                "rollback_success_rate": round(rollback_success_rate, 4),
            },
            "per_class_detection_rates": {
                "Corpus_F_Forgery": round(forgery_det_rate, 4),
                "Corpus_I_Impersonation": round(impersonation_det_rate, 4),
                "Corpus_R_Replay": round(replay_det_rate, 4),
                "Corpus_C_Channel_Manipulation": round(channel_det_rate, 4),
                "Corpus_E_Edge_Cases": round(edge_det_rate, 4),
            },
            "performance": {
                "mean_latency_ms": round(mean_latency * 1000, 3),
                "p95_latency_ms": round(p95_latency * 1000, 3),
                "throughput_verifications_per_second": round(throughput, 2),
            },
            "baseline_comparisons": {
                "Baseline_1_Fixed_QBER_Only": {
                    "detection_rate": round(b1_malicious_detected / total_malicious_tested, 4),
                    "far": round((total_malicious_tested - b1_malicious_detected) / total_malicious_tested, 4),
                    "note": "Fails to detect replays, identity spoofing, and message payload tampering",
                },
                "Baseline_2_QBER_Plus_TVD": {
                    "detection_rate": round(b2_malicious_detected / total_malicious_tested, 4),
                    "far": round((total_malicious_tested - b2_malicious_detected) / total_malicious_tested, 4),
                    "note": "Detects quantum distortion but blind to classical tampering and replay attacks",
                },
                "Eagle_Eye_Full_Framework": {
                    "detection_rate": round(overall_detection_rate, 4),
                    "far": round(far, 4),
                    "note": "Holistic defense combining guards, freshness, multi-statistic SPRT/QBER/TVD, and signed lifecycle",
                },
            },
            "target_gate_status": {
                "replay_rejection_target_100pct": replay_det_rate == 1.0,
                "honest_acceptance_target_gte_95pct": honest_acc_rate >= 0.95,
                "attack_detection_target_gte_90pct": overall_detection_rate >= 0.90,
                "far_target_lte_5pct": far <= 0.05,
                "latency_target_lte_1s": mean_latency <= 1.0,
                "evidence_completeness_100pct": evidence_completeness == 1.0,
                "rollback_success_100pct": rollback_success_rate == 1.0,
            },
        }

        return results


def run_benchmark_and_save_reports():
    runner = BenchmarkRunner(seeds_count=30)
    print("Executing Eagle-Eye benchmark suite across 30 seeds...")
    results = runner.run_full_benchmark()

    os.makedirs("reports", exist_ok=True)
    with open("reports/benchmark_results.json", "w") as f:
        json.dump(results, f, indent=2)

    # Format Markdown report
    pm = results["primary_metrics"]
    pcd = results["per_class_detection_rates"]
    perf = results["performance"]
    bc = results["baseline_comparisons"]
    tg = results["target_gate_status"]

    md_lines = [
        "# Eagle-Eye: Benchmark Evaluation Report",
        f"> **SIH PS 26141** | Evaluation Date: {results['meta']['evaluation_date']} | Seeds: {results['meta']['seeds_evaluated']}",
        "",
        "## 1. Executive Summary & Target Gate Status",
        "",
        "| Metric Target | Engineering Goal | Measured Result | Gate Status |",
        "|---|---|---|---|",
        f"| **Replay Rejection** | 100% | {pm['replay_rejection_rate']*100:.1f}% | {'[PASSED]' if tg['replay_rejection_target_100pct'] else '[FAILED]'} |",
        f"| **Honest Acceptance** | >= 95% | {pm['honest_acceptance_rate']*100:.1f}% | {'[PASSED]' if tg['honest_acceptance_target_gte_95pct'] else '[FAILED]'} |",
        f"| **Attack Detection** | >= 90% | {pm['overall_attack_detection_rate']*100:.1f}% | {'[PASSED]' if tg['attack_detection_target_gte_90pct'] else '[FAILED]'} |",
        f"| **False Acceptance Rate (FAR)** | <= 5% | {pm['far_false_acceptance_rate']*100:.1f}% | {'[PASSED]' if tg['far_target_lte_5pct'] else '[FAILED]'} |",
        f"| **Decision Latency (Mean)** | <= 1000 ms | {perf['mean_latency_ms']:.2f} ms | {'[PASSED]' if tg['latency_target_lte_1s'] else '[FAILED]'} |",
        f"| **Evidence Completeness** | 100% | {pm['evidence_completeness']*100:.1f}% | {'[PASSED]' if tg['evidence_completeness_100pct'] else '[FAILED]'} |",
        f"| **Rollback Success** | 100% | {pm['rollback_success_rate']*100:.1f}% | {'[PASSED]' if tg['rollback_success_100pct'] else '[FAILED]'} |",
        "",
        "## 2. Per-Class Attack Detection Rates",
        "",
        "| Attack Corpus | Category | Total Tested | Detection Rate |",
        "|---|---|---|---|",
        f"| **Corpus F** | Classical & Quantum Forgery | {results['meta']['seeds_evaluated'] * 4} | **{pcd['Corpus_F_Forgery']*100:.1f}%** |",
        f"| **Corpus I** | Signer & Context Impersonation | {results['meta']['seeds_evaluated'] * 3} | **{pcd['Corpus_I_Impersonation']*100:.1f}%** |",
        f"| **Corpus R** | Replay & Freshness Violations | {results['meta']['seeds_evaluated'] * 4} | **{pcd['Corpus_R_Replay']*100:.1f}%** |",
        f"| **Corpus C** | Channel Intercept-Resend & Jamming | {results['meta']['seeds_evaluated'] * 3} | **{pcd['Corpus_C_Channel_Manipulation']*100:.1f}%** |",
        f"| **Corpus E** | Stale Skew & Sample Edge Cases | {results['meta']['seeds_evaluated'] * 2} | **{pcd['Corpus_E_Edge_Cases']*100:.1f}%** |",
        "",
        "## 3. Comparative Architecture Analysis",
        "",
        "| Framework / Approach | Attack Detection Rate | False Acceptance (FAR) | Failure Modes & Vulnerabilities |",
        "|---|---|---|---|",
        f"| **Baseline 1 (Fixed QBER Only)** | {bc['Baseline_1_Fixed_QBER_Only']['detection_rate']*100:.1f}% | {bc['Baseline_1_Fixed_QBER_Only']['far']*100:.1f}% | {bc['Baseline_1_Fixed_QBER_Only']['note']} |",
        f"| **Baseline 2 (QBER + TVD)** | {bc['Baseline_2_QBER_Plus_TVD']['detection_rate']*100:.1f}% | {bc['Baseline_2_QBER_Plus_TVD']['far']*100:.1f}% | {bc['Baseline_2_QBER_Plus_TVD']['note']} |",
        f"| **Eagle-Eye (Full Framework)** | **{bc['Eagle_Eye_Full_Framework']['detection_rate']*100:.1f}%** | **{bc['Eagle_Eye_Full_Framework']['far']*100:.1f}%** | {bc['Eagle_Eye_Full_Framework']['note']} |",
        "",
        "## 4. Performance & Throughput",
        f"- **Mean Latency**: `{perf['mean_latency_ms']:.2f} ms`",
        f"- **95th Percentile Latency**: `{perf['p95_latency_ms']:.2f} ms`",
        f"- **Throughput**: `{perf['throughput_verifications_per_second']:.1f} verifications/sec`",
        f"- **Total Benchmark Decisions Evaluated**: `{results['meta']['total_decisions_evaluated']}`",
    ]

    with open("reports/BENCHMARK_REPORT.md", "w") as f:
        f.write("\n".join(md_lines))

    print("Benchmark complete! Saved reports/benchmark_results.json and reports/BENCHMARK_REPORT.md.")
    return results


if __name__ == "__main__":
    run_benchmark_and_save_reports()
