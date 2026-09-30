# Eagle-Eye — PRD to System Implementation Mapping

This matrix tracks the mapping from requirements in `Eagle-Eye — Product Requirements Document` (SIH PS 26141) to implementation modules, security controls, and verification test cases.

| Requirement ID | Description | Component Module | Implementation Artifacts | Verification Test Suites |
|---|---|---|---|---|
| **FR-01** | Protocol simulation (Bell-state distribution, teleportation, Pauli correction, X/Y/Z projective measurement) | `src.protocol` | `simulator.py`, `bell_state.py`, `teleportation.py`, `measurements.py` | `tests/unit/test_protocol.py`, `tests/integration/test_teleportation.py` |
| **FR-02** | Signature verification (message binding, identity/context, protocol state, measurement consistency, freshness) | `src.decision`, `src.guards` | `verifier.py`, `canonical.py`, `freshness.py` | `tests/unit/test_verifier.py`, `tests/integration/test_verification_pipeline.py` |
| **FR-03** | Forgery detection (statistical divergence, altered quantum signature states rejected/escalated) | `src.statistics`, `src.attacks` | `qber.py`, `distribution.py`, `forgery.py` | `tests/attacks/test_forgery.py` |
| **FR-04** | Impersonation detection (unknown signer, invalid key/state binding, identity mismatch) | `src.guards`, `src.attacks` | `identity.py`, `impersonation.py` | `tests/attacks/test_impersonation.py` |
| **FR-05** | Replay detection (nonce, timestamp, session identifier reuse rejected 100%) | `src.guards`, `src.attacks` | `freshness.py`, `replay.py`, `sliding_window.py` | `tests/attacks/test_replay.py` |
| **FR-06** | Channel manipulation detection (QBER, basis error rates, distribution distance, confidence bounds) | `src.statistics`, `src.attacks` | `qber.py`, `bounds.py`, `channel_manipulation.py` | `tests/attacks/test_channel.py` |
| **FR-07** | Unauthorized verification detection (verifier identity, role, purpose, rate limiting) | `src.guards`, `src.attacks` | `auth.py`, `rate_limiter.py`, `unauthorized.py` | `tests/attacks/test_unauthorized.py` |
| **FR-08** | Evidence & audit chain (hash-linked event chain, parameter capture, tamper evidence) | `src.audit`, `src.schemas` | `audit_ledger.py`, `hash_chain.py` | `tests/security/test_audit_chain.py` |
| **FR-09** | Controlled self-healing (incident confirmation, rule proposal, shadow test, approval, rollback) | `src.self_healing` | `engine.py`, `rule_bundle.py`, `shadow_runner.py` | `tests/resilience/test_self_healing.py` |
| **FR-10** | Reporting & Benchmark evaluation (explainable verification outputs, reproducible benchmark suite) | `src.dashboard`, `src.benchmark` | `report_generator.py`, `benchmark_runner.py`, `app.py` | `tests/benchmark/test_benchmark_metrics.py` |

## Non-Functional Requirements & Governance Controls
- **Explainability**: Every decision packet contains structured reason codes, measured metrics, statistical intervals, and threshold comparisons.
- **Determinism**: Every run supports an explicit RNG seed. With identical seed and inputs, results are 100% reproducible.
- **Fail-Closed Security**: Any malformed input, clock skew breach, unauthenticated verifier, or policy hash mismatch results in an immediate fail-closed `REJECT`.
- **Zero AI/ML**: No heuristics, no neural networks. Detection is built purely on quantum information theory and statistical hypothesis testing (Wilson score, SPRT, TVD).
