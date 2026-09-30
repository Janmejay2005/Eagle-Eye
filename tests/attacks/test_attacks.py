"""
Unit and scenario tests for parameterized attacks.
Acceptance Gate 5: Each scenario triggers intended reason/escalation.
"""
import pytest
import numpy as np

from src.schemas import Message, Policy, Session, Identity, IdentityRole
from src.protocol import QDSSimulator
from src.guards import (
    CanonicalBindingGuard,
    IdentityGuard,
    IdentityRegistry,
    FreshnessGuard,
    RateLimiter,
)
from src.statistics import StatisticalEvaluator
from src.attacks import (
    ForgerySimulator,
    ImpersonationSimulator,
    ReplaySimulator,
    ChannelAttackSimulator,
    UnauthorizedVerificationSimulator,
)


@pytest.fixture
def test_setup():
    registry = IdentityRegistry()
    alice = Identity(
        identity_id="alice@qds.bank",
        name="Alice Signer",
        role=IdentityRole.SIGNER,
        public_key_hex="aaaabbbbccccdddd",
        is_authorized=True,
        permissions=["sign"],
    )
    bob = Identity(
        identity_id="bob@qds.bank",
        name="Bob Verifier",
        role=IdentityRole.VERIFIER,
        public_key_hex="eeeeffff11112222",
        is_authorized=True,
        permissions=["verify"],
    )
    registry.register(alice, secret_key="alice-super-secret-key")
    registry.register(bob)

    identity_guard = IdentityGuard(registry)
    freshness_guard = FreshnessGuard()
    policy = Policy(
        max_qber_threshold=0.08,
        escalate_qber_threshold=0.045,
        max_tvd_threshold=0.15,
        max_clock_skew_seconds=10.0,
    )

    session = Session(
        session_id="sess-attacks-001",
        signer_id="alice@qds.bank",
        verifier_id="bob@qds.bank",
        created_at=1727700000.0,
        expires_at=1727703600.0,
    )
    freshness_guard.register_session(session)

    simulator = QDSSimulator(seed=42)
    message = Message.create(
        message_id="msg-transfer-100",
        payload="Transfer 50,000 INR to Charlie",
        sender_id="alice@qds.bank",
        receiver_id="bob@qds.bank",
        timestamp=1727700010.0,
    )

    sig, batch = simulator.generate_honest_signature_and_measurements(
        message=message,
        signer_key="alice-super-secret-key",
        session_id="sess-attacks-001",
        nonce="attack-nonce-11223344",
        qubit_count=64,
    )

    return {
        "registry": registry,
        "identity_guard": identity_guard,
        "freshness_guard": freshness_guard,
        "policy": policy,
        "session": session,
        "simulator": simulator,
        "message": message,
        "signature": sig,
        "batch": batch,
    }


def test_forgery_message_payload_tampering(test_setup):
    """Scenario 1: Tampered message payload triggers message digest mismatch."""
    msg = test_setup["message"]
    sig = test_setup["signature"]

    tampered_msg = ForgerySimulator.tamper_message_payload(msg, "Transfer 5,000,000 INR to Eve")
    ok, reason = CanonicalBindingGuard.verify_message_integrity(tampered_msg)
    assert not ok
    assert "MESSAGE_DIGEST_MISMATCH" in reason

    # Signature binding to tampered message also fails
    ok_bind, reason_bind = CanonicalBindingGuard.verify_signature_binding(
        sig, tampered_msg, "alice-super-secret-key"
    )
    assert not ok_bind
    assert "CANONICAL_BINDING_MISMATCH" in reason_bind


def test_forgery_quantum_state_tampering(test_setup):
    """Scenario 2: Tampered quantum state bits trigger QBER and TVD threshold violations."""
    sig = test_setup["signature"]
    policy = test_setup["policy"]

    tampered_sig = ForgerySimulator.tamper_quantum_measurements(sig, flip_fraction=0.4, seed=123)
    evaluator = StatisticalEvaluator()
    summary = evaluator.evaluate_batch(tampered_sig.measurements, policy)

    assert summary.qber > policy.max_qber_threshold
    assert summary.exceeds_hard_qber
    assert summary.sprt_verdict == "ATTACK"


def test_impersonation_unregistered_signer(test_setup):
    """Scenario 3: Unregistered signer identity triggers UNKNOWN_SIGNER."""
    sig = test_setup["signature"]
    guard = test_setup["identity_guard"]

    spoofed_sig = ImpersonationSimulator.spoof_unregistered_signer(sig, "eve@attacker-domain.org")
    ok, reason = guard.verify_signer(spoofed_sig.signer_identity)
    assert not ok
    assert "UNKNOWN_SIGNER" in reason


def test_replay_duplicate_nonce(test_setup):
    """Scenario 4: Replay of identical valid signature triggers REPLAY_DETECTED_NONCE_REUSE."""
    sig = test_setup["signature"]
    guard = test_setup["freshness_guard"]
    policy = test_setup["policy"]
    now = 1727700012.0

    # First attempt succeeds
    ok1, reason1, _ = guard.check_freshness_and_replay(sig, policy, current_time=now)
    assert ok1

    # Replayed attempt fails 100%
    replayed_sig = ReplaySimulator.create_identical_replay(sig)
    ok2, reason2, evidence = guard.check_freshness_and_replay(replayed_sig, policy, current_time=now + 1.0)
    assert not ok2
    assert "REPLAY_DETECTED_NONCE_REUSE" in reason2
    assert evidence["replay_detected"] == "true"


def test_replay_stale_timestamp(test_setup):
    """Scenario 5: Stale timestamp beyond clock skew triggers STALE_TIMESTAMP."""
    sig = test_setup["signature"]
    guard = test_setup["freshness_guard"]
    policy = test_setup["policy"]
    now = 1727700012.0

    stale_sig = ReplaySimulator.create_stale_replay(sig, stale_seconds=120.0)
    ok, reason, _ = guard.check_freshness_and_replay(stale_sig, policy, current_time=now)
    assert not ok
    assert "STALE_TIMESTAMP" in reason


def test_channel_intercept_resend_attack(test_setup):
    """Scenario 6: Intercept-resend attack triggers high QBER and SPRT ATTACK."""
    sim = test_setup["simulator"]
    msg = test_setup["message"]
    policy = test_setup["policy"]

    sig_int, batch_int = ChannelAttackSimulator.simulate_intercept_resend(
        simulator=sim,
        message=msg,
        signer_key="alice-super-secret-key",
        session_id="sess-attacks-001",
        nonce="intercept-nonce-9999",
        qubit_count=64,
        seed=777,
    )

    evaluator = StatisticalEvaluator()
    summary = evaluator.evaluate_batch(batch_int, policy)

    assert summary.qber > policy.max_qber_threshold
    assert summary.exceeds_hard_qber
    assert summary.sprt_verdict == "ATTACK"


def test_unauthorized_verifier_and_rate_limit(test_setup):
    """Scenario 7: Unauthorized verifier and rate limit flood are blocked."""
    guard = test_setup["identity_guard"]
    ok, reason = UnauthorizedVerificationSimulator.simulate_unregistered_verifier_probe(
        guard, "rogue-agent@unknown.net"
    )
    assert not ok
    assert "UNKNOWN_VERIFIER" in reason

    limiter = RateLimiter(window_seconds=60.0)
    results = UnauthorizedVerificationSimulator.simulate_rate_limit_flood(
        limiter, entity_id="bob@qds.bank", limit=5, excess_requests=3
    )
    # First 5 should succeed, remaining 3 should be rejected
    allowed_list = [r[0] for r in results]
    assert allowed_list == [True, True, True, True, True, False, False, False]
