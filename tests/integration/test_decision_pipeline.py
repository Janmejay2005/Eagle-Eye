"""
Integration tests for the complete Decision and Response engine.
Acceptance Gate 6: Every decision deterministic, explainable, auditable.
"""
import pytest
import numpy as np

from src.schemas import (
    Message,
    Policy,
    Session,
    Identity,
    IdentityRole,
    Verdict,
)
from src.protocol import QDSSimulator, QuantumNoiseChannel
from src.guards import IdentityRegistry, FreshnessGuard
from src.decision import VerificationEngine, AuditLedger, VerificationReportGenerator
from src.attacks import (
    ForgerySimulator,
    ChannelAttackSimulator,
    ReplaySimulator,
)


@pytest.fixture
def verification_env():
    registry = IdentityRegistry()
    alice = Identity(
        identity_id="alice@qds.bank",
        name="Alice Signer",
        role=IdentityRole.SIGNER,
        public_key_hex="a1b2c3d4e5f60718293a4b5c6d7e8f90",
        is_authorized=True,
        permissions=["sign"],
    )
    bob = Identity(
        identity_id="bob@qds.bank",
        name="Bob Verifier",
        role=IdentityRole.VERIFIER,
        public_key_hex="18293a4b5c6d7e8fa1b2c3d4e5f60718",
        is_authorized=True,
        permissions=["verify"],
    )
    registry.register(alice, secret_key="alice-private-key-12345")
    registry.register(bob)

    freshness_guard = FreshnessGuard()
    audit_ledger = AuditLedger()

    policy = Policy(
        max_qber_threshold=0.08,
        escalate_qber_threshold=0.04,
        max_tvd_threshold=0.15,
        max_clock_skew_seconds=10.0,
        min_qubit_sample_size=16,
    )

    engine = VerificationEngine(
        registry=registry,
        freshness_guard=freshness_guard,
        audit_ledger=audit_ledger,
    )

    simulator = QDSSimulator(seed=123)

    return {
        "engine": engine,
        "freshness_guard": freshness_guard,
        "audit_ledger": audit_ledger,
        "policy": policy,
        "simulator": simulator,
        "alice": alice,
        "bob": bob,
    }


def test_verdict_accept_under_ideal_conditions(verification_env):
    """Mandatory test: Valid signature under ideal conditions -> ACCEPT."""
    env = verification_env
    now = 1727700010.0
    session = Session(
        session_id="sess-ideal-001",
        signer_id="alice@qds.bank",
        verifier_id="bob@qds.bank",
        created_at=1727700000.0,
        expires_at=1727703600.0,
    )
    env["freshness_guard"].register_session(session)

    message = Message.create(
        message_id="msg-ideal-001",
        payload="Authorize settlement payment 25,000 INR",
        sender_id="alice@qds.bank",
        receiver_id="bob@qds.bank",
        timestamp=now,
    )

    sig, batch = env["simulator"].generate_honest_signature_and_measurements(
        message=message,
        signer_key="alice-private-key-12345",
        session_id=session.session_id,
        nonce="nonce-ideal-9999",
        qubit_count=32,
        noise_channel=None,
        timestamp=now,
    )

    decision = env["engine"].verify(
        message=message,
        signature=sig,
        verifier_identity_id="bob@qds.bank",
        policy=env["policy"],
        current_time=now,
    )

    assert decision.verdict == Verdict.ACCEPT
    assert "SIGNATURE_AND_QUANTUM_METRICS_VERIFIED_SUCCESSFULLY" in decision.reasons
    assert decision.failed_checks == []
    assert decision.statistics["qber"] == 0.0
    assert decision.event_hash is not None


def test_verdict_controlled_escalate_under_honest_noise(verification_env):
    """Mandatory test: Honest signature under declared noise -> ACCEPT or controlled ESCALATE."""
    env = verification_env
    now = 1727700020.0
    session = Session(
        session_id="sess-noise-001",
        signer_id="alice@qds.bank",
        verifier_id="bob@qds.bank",
        created_at=1727700000.0,
        expires_at=1727703600.0,
    )
    env["freshness_guard"].register_session(session)

    message = Message.create(
        message_id="msg-noise-001",
        payload="Normal noise transaction",
        sender_id="alice@qds.bank",
        receiver_id="bob@qds.bank",
        timestamp=now,
    )

    # Moderate noise channel causing ~5-6% QBER (between 0.04 escalate and 0.08 reject)
    noise = QuantumNoiseChannel(depolarizing_rate=0.07, seed=77)
    sig, batch = env["simulator"].generate_honest_signature_and_measurements(
        message=message,
        signer_key="alice-private-key-12345",
        session_id=session.session_id,
        nonce="nonce-noise-8888",
        qubit_count=64,
        noise_channel=noise,
        timestamp=now,
    )

    decision = env["engine"].verify(
        message=message,
        signature=sig,
        verifier_identity_id="bob@qds.bank",
        policy=env["policy"],
        current_time=now,
    )

    assert decision.verdict in (Verdict.ACCEPT, Verdict.ESCALATE)
    if decision.verdict == Verdict.ESCALATE:
        assert any("ESCALATE" in r for r in decision.reasons)


def test_verdict_reject_and_quarantine_on_channel_disturbance(verification_env):
    """Mandatory test: Channel disturbance -> statistical evidence, REJECT, and session quarantine."""
    env = verification_env
    now = 1727700030.0
    session = Session(
        session_id="sess-channel-attack-001",
        signer_id="alice@qds.bank",
        verifier_id="bob@qds.bank",
        created_at=1727700000.0,
        expires_at=1727703600.0,
    )
    env["freshness_guard"].register_session(session)

    message = Message.create(
        message_id="msg-disturb-001",
        payload="Critical state transfer",
        sender_id="alice@qds.bank",
        receiver_id="bob@qds.bank",
        timestamp=now,
    )

    # Severe channel disruption: 30% noise
    sig, batch = ChannelAttackSimulator.simulate_high_depolarizing_burst(
        simulator=env["simulator"],
        message=message,
        signer_key="alice-private-key-12345",
        session_id=session.session_id,
        nonce="nonce-disturb-7777",
        qubit_count=64,
        noise_rate=0.30,
    )

    decision = env["engine"].verify(
        message=message,
        signature=sig,
        verifier_identity_id="bob@qds.bank",
        policy=env["policy"],
        current_time=now,
    )

    assert decision.verdict == Verdict.REJECT
    assert "QUANTUM_SECURITY_BOUNDS_EXCEEDED" in decision.failed_checks
    # Channel must be quarantined!
    updated_sess = env["freshness_guard"].get_session(session.session_id)
    assert updated_sess.is_quarantined is True


def test_audit_ledger_chain_and_tampering_detection(verification_env):
    """Audit ledger verifies unbroken hash chain and catches retroactive tampering."""
    env = verification_env
    ledger = env["audit_ledger"]

    # Generate a couple of decisions first
    now = 1727700050.0
    session = Session(
        session_id="sess-audit-001",
        signer_id="alice@qds.bank",
        verifier_id="bob@qds.bank",
        created_at=1727700000.0,
        expires_at=1727703600.0,
    )
    env["freshness_guard"].register_session(session)

    msg = Message.create("msg-audit-1", "Audit transaction 1", "alice@qds.bank", "bob@qds.bank", timestamp=now)
    sig, _ = env["simulator"].generate_honest_signature_and_measurements(
        message=msg,
        signer_key="alice-private-key-12345",
        session_id=session.session_id,
        nonce="audit-nonce-001",
        qubit_count=16,
        timestamp=now,
    )
    env["engine"].verify(msg, sig, "bob@qds.bank", env["policy"], current_time=now)

    # Verify integrity of chain
    is_valid, msg = ledger.verify_chain_integrity()
    assert is_valid

    # Now tamper with one of the past decisions in the ledger
    assert len(ledger._chain) > 0
    original_verdict = ledger._chain[0].verdict
    ledger._chain[0].verdict = Verdict.REJECT  # Maliciously flip verdict in historical log

    is_tampered_valid, tamper_msg = ledger.verify_chain_integrity()
    assert not is_tampered_valid
    assert "TAMPER_DETECTED" in tamper_msg

    # Restore
    ledger._chain[0].verdict = original_verdict


def test_report_generator(verification_env):
    """Reports are correctly generated in JSON and Markdown formats."""
    env = verification_env
    now = 1727700060.0
    session = Session(
        session_id="sess-rep-001",
        signer_id="alice@qds.bank",
        verifier_id="bob@qds.bank",
        created_at=1727700000.0,
        expires_at=1727703600.0,
    )
    env["freshness_guard"].register_session(session)

    msg = Message.create("msg-rep-1", "Report transaction", "alice@qds.bank", "bob@qds.bank", timestamp=now)
    sig, _ = env["simulator"].generate_honest_signature_and_measurements(
        message=msg,
        signer_key="alice-private-key-12345",
        session_id=session.session_id,
        nonce="rep-nonce-001",
        qubit_count=16,
        timestamp=now,
    )
    dec = env["engine"].verify(msg, sig, "bob@qds.bank", env["policy"], current_time=now)

    chain = env["audit_ledger"].chain
    json_out = VerificationReportGenerator.generate_json_report(chain)
    assert len(json_out) > 50

    md_out = VerificationReportGenerator.generate_markdown_summary(dec)
    assert "# Verification Event:" in md_out
    assert "Verdict" in md_out
