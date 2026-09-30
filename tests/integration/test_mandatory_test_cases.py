"""
Direct implementation of Section 3 'Mandatory test cases' from Eagle-Eye — Testing.md.
Every test case defines input, expected reason, expected decision, versions, seed, sample size, and tolerance.

Mandatory Test Cases:
1. Valid signature under ideal conditions -> ACCEPT
2. Honest signature under declared noise -> ACCEPT or controlled ESCALATE
3. Modified message with original signature -> REJECT
4. Forged signature -> REJECT or ESCALATE with reason
5. Unknown signer/context -> REJECT
6. Valid signature replayed with same nonce/session -> REJECT
7. Stale timestamp or clock skew -> REJECT/ESCALATE
8. Channel disturbance -> statistical evidence and correct decision
9. Unauthorised verifier -> deny disclosure and log
10. Tampered policy/audit -> integrity failure and fail closed
11. Confirmed incident -> update only after regression tests
12. Bad update -> rollback and retain evidence
"""
import time
import pytest

from src.schemas import (
    Message,
    Signature,
    Policy,
    Session,
    Identity,
    IdentityRole,
    Verdict,
    Incident,
    AttackType,
    IncidentSeverity,
)
from src.protocol import QDSSimulator, QuantumNoiseChannel
from src.guards import IdentityRegistry, FreshnessGuard, RateLimiter
from src.decision.verifier import VerificationEngine
from src.decision.audit_ledger import AuditLedger
from src.decision.report_generator import VerificationReportGenerator
from src.attacks import (
    ForgerySimulator,
    ImpersonationSimulator,
    ReplaySimulator,
    ChannelAttackSimulator,
    UnauthorizedVerificationSimulator,
)
from src.self_healing import (
    SelfHealingEngine,
    generate_ed25519_keypair,
    sign_payload,
    verify_payload_signature,
    ShadowRegressionError,
)


@pytest.fixture
def env():
    registry = IdentityRegistry()
    priv, pub = generate_ed25519_keypair()
    admin = Identity(
        identity_id="admin@qds.bank",
        name="Admin",
        role=IdentityRole.ADMIN,
        public_key_hex=pub,
        is_authorized=True,
        permissions=["admin", "verify"],
    )
    alice = Identity(
        identity_id="alice@qds.bank",
        name="Alice Signer",
        role=IdentityRole.SIGNER,
        public_key_hex="alice-pub",
        is_authorized=True,
        permissions=["sign"],
    )
    bob = Identity(
        identity_id="bob@qds.bank",
        name="Bob Verifier",
        role=IdentityRole.VERIFIER,
        public_key_hex="bob-pub",
        is_authorized=True,
        permissions=["verify"],
    )
    registry.register(admin)
    registry.register(alice, secret_key="alice-hsm-secret")
    registry.register(bob)

    guard = FreshnessGuard()
    ledger = AuditLedger()
    policy = Policy(
        policy_id="mandatory-policy-v1",
        version="1.0.0",
        max_qber_threshold=0.08,
        escalate_qber_threshold=0.045,
        max_tvd_threshold=0.15,
        confidence_level=0.95,
        max_clock_skew_seconds=10.0,
        min_qubit_sample_size=16,
    )
    engine = VerificationEngine(registry=registry, freshness_guard=guard, audit_ledger=ledger)
    sim = QDSSimulator(seed=42)

    now = 1727700000.0
    session = Session(
        session_id="sess-mandatory-001",
        signer_id=alice.identity_id,
        verifier_id=bob.identity_id,
        created_at=now - 100,
        expires_at=now + 3600,
    )
    guard.register_session(session)

    return {
        "engine": engine,
        "registry": registry,
        "guard": guard,
        "ledger": ledger,
        "policy": policy,
        "sim": sim,
        "session": session,
        "admin": admin,
        "admin_priv": priv,
        "admin_pub": pub,
        "alice": alice,
        "bob": bob,
        "now": now,
    }


def test_case_01_valid_signature_under_ideal_conditions_accept(env):
    """Mandatory Test 1: Valid signature under ideal conditions -> ACCEPT."""
    msg = Message.create("msg-01", "Pay 10,000 INR", env["alice"].identity_id, env["bob"].identity_id, timestamp=env["now"])
    sig, _ = env["sim"].generate_honest_signature_and_measurements(
        message=msg,
        signer_key="alice-hsm-secret",
        session_id=env["session"].session_id,
        nonce="nonce-ideal-001",
        qubit_count=32,
        noise_channel=None,
        timestamp=env["now"],
    )
    dec = env["engine"].verify(msg, sig, env["bob"].identity_id, env["policy"], current_time=env["now"])
    assert dec.verdict == Verdict.ACCEPT
    assert "SIGNATURE_AND_QUANTUM_METRICS_VERIFIED_SUCCESSFULLY" in dec.reasons
    assert dec.failed_checks == []


def test_case_02_honest_signature_under_declared_noise_accept_or_escalate(env):
    """Mandatory Test 2: Honest signature under declared noise -> ACCEPT or controlled ESCALATE."""
    now = env["now"] + 10
    msg = Message.create("msg-02", "Pay with noise", env["alice"].identity_id, env["bob"].identity_id, timestamp=now)
    noise = QuantumNoiseChannel(depolarizing_rate=0.06, seed=888)
    sig, _ = env["sim"].generate_honest_signature_and_measurements(
        message=msg,
        signer_key="alice-hsm-secret",
        session_id=env["session"].session_id,
        nonce="nonce-noise-002",
        qubit_count=64,
        noise_channel=noise,
        timestamp=now,
    )
    dec = env["engine"].verify(msg, sig, env["bob"].identity_id, env["policy"], current_time=now)
    assert dec.verdict in (Verdict.ACCEPT, Verdict.ESCALATE)
    if dec.verdict == Verdict.ESCALATE:
        assert any("ESCALATE" in r for r in dec.reasons)


def test_case_03_modified_message_with_original_signature_reject(env):
    """Mandatory Test 3: Modified message with original signature -> REJECT."""
    now = env["now"] + 20
    msg = Message.create("msg-03", "Transfer 1,000 INR", env["alice"].identity_id, env["bob"].identity_id, timestamp=now)
    sig, _ = env["sim"].generate_honest_signature_and_measurements(
        message=msg,
        signer_key="alice-hsm-secret",
        session_id=env["session"].session_id,
        nonce="nonce-mod-003",
        qubit_count=32,
        timestamp=now,
    )
    tampered_msg = ForgerySimulator.tamper_message_payload(msg, "Transfer 1,000,000 INR to Attacker")
    dec = env["engine"].verify(tampered_msg, sig, env["bob"].identity_id, env["policy"], current_time=now)
    assert dec.verdict == Verdict.REJECT
    assert "MESSAGE_INTEGRITY" in dec.failed_checks


def test_case_04_forged_signature_reject_or_escalate_with_reason(env):
    """Mandatory Test 4: Forged signature -> REJECT or ESCALATE with reason."""
    now = env["now"] + 30
    msg = Message.create("msg-04", "Forged state test", env["alice"].identity_id, env["bob"].identity_id, timestamp=now)
    sig, _ = env["sim"].generate_honest_signature_and_measurements(
        message=msg,
        signer_key="alice-hsm-secret",
        session_id=env["session"].session_id,
        nonce="nonce-forg-004",
        qubit_count=32,
        timestamp=now,
    )
    tampered_sig = ForgerySimulator.tamper_quantum_measurements(sig, flip_fraction=0.45, seed=99)
    dec = env["engine"].verify(msg, tampered_sig, env["bob"].identity_id, env["policy"], current_time=now)
    assert dec.verdict == Verdict.REJECT
    assert len(dec.reasons) > 0
    assert any("ANOMALOUS_QUANTUM_METRICS" in r for r in dec.reasons)


def test_case_05_unknown_signer_context_reject(env):
    """Mandatory Test 5: Unknown signer/context -> REJECT."""
    now = env["now"] + 40
    msg = Message.create("msg-05", "Unregistered sender", "unknown_mallory@qds.bank", env["bob"].identity_id, timestamp=now)
    sig, _ = env["sim"].generate_honest_signature_and_measurements(
        message=msg,
        signer_key="dummy-key",
        session_id=env["session"].session_id,
        nonce="nonce-unknown-005",
        qubit_count=32,
        timestamp=now,
    )
    dec = env["engine"].verify(msg, sig, env["bob"].identity_id, env["policy"], current_time=now)
    assert dec.verdict == Verdict.REJECT
    assert "SIGNER_IDENTITY" in dec.failed_checks


def test_case_06_valid_signature_replayed_with_same_nonce_session_reject(env):
    """Mandatory Test 6: Valid signature replayed with same nonce/session -> REJECT."""
    now = env["now"] + 50
    msg = Message.create("msg-06", "Original voucher", env["alice"].identity_id, env["bob"].identity_id, timestamp=now)
    sig, _ = env["sim"].generate_honest_signature_and_measurements(
        message=msg,
        signer_key="alice-hsm-secret",
        session_id=env["session"].session_id,
        nonce="nonce-replay-006",
        qubit_count=32,
        timestamp=now,
    )
    # First attempt: ACCEPT
    dec1 = env["engine"].verify(msg, sig, env["bob"].identity_id, env["policy"], current_time=now)
    assert dec1.verdict == Verdict.ACCEPT

    # Replay attempt: REJECT
    replayed = ReplaySimulator.create_identical_replay(sig)
    dec2 = env["engine"].verify(msg, replayed, env["bob"].identity_id, env["policy"], current_time=now + 1.0)
    assert dec2.verdict == Verdict.REJECT
    assert "FRESHNESS_OR_REPLAY" in dec2.failed_checks
    assert any("REPLAY_DETECTED" in r for r in dec2.reasons)


def test_case_07_stale_timestamp_or_clock_skew_reject_escalate(env):
    """Mandatory Test 7: Stale timestamp or clock skew -> REJECT/ESCALATE."""
    now = env["now"] + 60
    msg = Message.create("msg-07", "Stale request", env["alice"].identity_id, env["bob"].identity_id, timestamp=now)
    sig, _ = env["sim"].generate_honest_signature_and_measurements(
        message=msg,
        signer_key="alice-hsm-secret",
        session_id=env["session"].session_id,
        nonce="nonce-stale-007",
        qubit_count=32,
        timestamp=now - 50.0,  # 50s old (> 10s skew)
    )
    dec = env["engine"].verify(msg, sig, env["bob"].identity_id, env["policy"], current_time=now)
    assert dec.verdict == Verdict.REJECT
    assert "FRESHNESS_OR_REPLAY" in dec.failed_checks
    assert any("STALE_TIMESTAMP" in r for r in dec.reasons)


def test_case_08_channel_disturbance_statistical_evidence_and_correct_decision(env):
    """Mandatory Test 8: Channel disturbance -> statistical evidence and correct decision."""
    now = env["now"] + 70
    msg = Message.create("msg-08", "Channel disturbance packet", env["alice"].identity_id, env["bob"].identity_id, timestamp=now)
    sig, batch = ChannelAttackSimulator.simulate_intercept_resend(
        simulator=env["sim"],
        message=msg,
        signer_key="alice-hsm-secret",
        session_id=env["session"].session_id,
        nonce="nonce-chan-008",
        qubit_count=64,
        seed=101,
    )
    dec = env["engine"].verify(msg, sig, env["bob"].identity_id, env["policy"], current_time=now)
    assert dec.verdict == Verdict.REJECT
    assert "QUANTUM_SECURITY_BOUNDS_EXCEEDED" in dec.failed_checks
    assert "qber" in dec.statistics
    assert "mean_tvd" in dec.statistics
    assert "sprt_verdict" in dec.statistics


def test_case_09_unauthorised_verifier_deny_disclosure_and_log(env):
    """Mandatory Test 9: Unauthorised verifier -> deny disclosure and log."""
    now = env["now"] + 80
    msg = Message.create("msg-09", "Secure bank info", env["alice"].identity_id, env["bob"].identity_id, timestamp=now)
    sig, _ = env["sim"].generate_honest_signature_and_measurements(
        message=msg,
        signer_key="alice-hsm-secret",
        session_id=env["session"].session_id,
        nonce="nonce-unauth-009",
        qubit_count=32,
        timestamp=now,
    )
    dec = env["engine"].verify(msg, sig, "unauthorized_verifier_spy@qds.bank", env["policy"], current_time=now)
    assert dec.verdict == Verdict.REJECT
    assert "VERIFIER_AUTHORIZATION" in dec.failed_checks
    assert any("UNKNOWN_VERIFIER" in r for r in dec.reasons)
    # Decision is safely recorded in audit ledger
    assert dec.event_hash is not None


def test_case_10_tampered_policy_or_audit_integrity_failure_and_fail_closed(env):
    """Mandatory Test 10: Tampered policy/audit -> integrity failure and fail closed."""
    # 1. Audit chain tampering detection
    msg = Message.create("msg-10", "Integrity check", env["alice"].identity_id, env["bob"].identity_id, timestamp=env["now"])
    sig, _ = env["sim"].generate_honest_signature_and_measurements(
        message=msg,
        signer_key="alice-hsm-secret",
        session_id=env["session"].session_id,
        nonce="nonce-audit-010",
        qubit_count=16,
        timestamp=env["now"],
    )
    env["engine"].verify(msg, sig, env["bob"].identity_id, env["policy"], current_time=env["now"])

    ledger = env["ledger"]
    assert len(ledger._chain) > 0
    # Tamper with an event in ledger
    ledger._chain[-1].reasons = ["MALICIOUS_TAMPERED_REASON"]
    is_valid, msg = ledger.verify_chain_integrity()
    assert not is_valid
    assert "TAMPER_DETECTED" in msg

    # 2. Tampered policy signature fails closed
    sh_engine = SelfHealingEngine(env["policy"])
    candidate = env["policy"].model_copy()
    candidate.version = "1.0.9-tampered"
    bundle = sh_engine.propose_update(candidate, "Tampered proposal")
    sh_engine.run_shadow_tests(bundle.bundle_id)
    sh_engine.approve_and_sign(bundle.bundle_id, env["admin"], env["admin_priv"])
    # Tamper with the signature bytes
    bundle.ed25519_signature = "bad" + bundle.ed25519_signature[3:]
    with pytest.raises(Exception):
        sh_engine.apply_update(bundle.bundle_id, env["admin_pub"])


def test_case_11_confirmed_incident_update_only_after_regression_tests(env):
    """Mandatory Test 11: Confirmed incident -> update only after regression tests."""
    sh_engine = SelfHealingEngine(env["policy"])
    candidate = env["policy"].model_copy()
    candidate.version = "1.0.1"

    bundle = sh_engine.propose_update(candidate, "Update after incident", incident_id="INC-011")

    # Attempting approval without shadow test MUST fail
    with pytest.raises(ShadowRegressionError):
        sh_engine.approve_and_sign(bundle.bundle_id, env["admin"], env["admin_priv"])

    # Run shadow regression test
    passed, metrics = sh_engine.run_shadow_tests(bundle.bundle_id)
    assert passed
    assert metrics["honest_acceptance_rate"] >= 0.95

    # Now approval succeeds
    sh_engine.approve_and_sign(bundle.bundle_id, env["admin"], env["admin_priv"])
    assert bundle.ed25519_signature is not None


def test_case_12_bad_update_rollback_and_retain_evidence(env):
    """Mandatory Test 12: Bad update -> rollback and retain evidence."""
    sh_engine = SelfHealingEngine(env["policy"])
    candidate = env["policy"].model_copy()
    candidate.version = "1.1.0"
    candidate.max_clock_skew_seconds = 7.0

    bundle = sh_engine.propose_update(candidate, "Calibrate clock skew", incident_id="INC-012")
    sh_engine.run_shadow_tests(bundle.bundle_id)
    sh_engine.approve_and_sign(bundle.bundle_id, env["admin"], env["admin_priv"])

    ckpt = sh_engine.apply_update(bundle.bundle_id, env["admin_pub"])
    assert sh_engine.active_policy.version == "1.1.0"

    # Rollback
    restored = sh_engine.rollback(ckpt)
    assert restored.version == "1.0.0"
    assert sh_engine.active_policy.version == "1.0.0"
    # Evidence retained in bundle
    assert bundle.incident_id == "INC-012"
    assert bundle.ed25519_signature is not None
