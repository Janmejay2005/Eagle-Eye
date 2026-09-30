"""
Unit tests for Eagle-Eye guards: Canonical binding, identity, freshness, and anti-replay.
Acceptance Gate 3: Replay and identity tests pass first.
"""
import time
import pytest

from src.schemas import (
    Message,
    Identity,
    IdentityRole,
    Session,
    Policy,
    Signature,
    compute_canonical_binding,
)
from src.guards import (
    CanonicalBindingGuard,
    IdentityGuard,
    IdentityRegistry,
    FreshnessGuard,
    RateLimiter,
)
from tests.fixtures.sample_data import (
    get_sample_message,
    get_sample_identity,
    get_sample_signature,
    get_sample_policy,
)


def test_identity_guard_verification():
    """Identity guard verifies authorized entities and rejects unknown or revoked entities."""
    registry = IdentityRegistry()
    guard = IdentityGuard(registry)

    # Unknown signer rejected
    ok, reason = guard.verify_signer("unknown-alice")
    assert not ok
    assert "UNKNOWN_SIGNER" in reason

    # Register valid signer
    alice = get_sample_identity()
    registry.register(alice, secret_key="alice-key-123")
    ok, reason = guard.verify_signer(alice.identity_id)
    assert ok
    assert reason == "SIGNER_IDENTITY_VALID"

    # Revoked signer rejected
    registry.revoke(alice.identity_id)
    ok, reason = guard.verify_signer(alice.identity_id)
    assert not ok
    assert "REVOKED_SIGNER" in reason

    # Verifier role check
    bob = Identity(
        identity_id="bob@qds.bank",
        name="Bob Verifier",
        role=IdentityRole.VERIFIER,
        public_key_hex="abcdef1234567890",
        is_authorized=True,
        permissions=["verify"],
    )
    registry.register(bob)
    ok, reason = guard.verify_verifier(bob.identity_id)
    assert ok
    assert reason == "VERIFIER_IDENTITY_VALID"

    # Signer attempting verifier action rejected
    carol = Identity(
        identity_id="carol@qds.bank",
        name="Carol Signer",
        role=IdentityRole.SIGNER,
        public_key_hex="1234567890abcdef",
        is_authorized=True,
        permissions=["sign"],
    )
    registry.register(carol)
    ok, reason = guard.verify_verifier(carol.identity_id)
    assert not ok
    assert "INVALID_VERIFIER_ROLE" in reason


def test_canonical_binding_guard():
    """Canonical binding checks fail on tampered payload, mismatched ID, or wrong secret key."""
    msg = get_sample_message()
    sig = get_sample_signature()

    # Valid message & signature binding
    ok, reason = CanonicalBindingGuard.verify_message_integrity(msg)
    assert ok

    ok, reason = CanonicalBindingGuard.verify_signature_binding(sig, msg, "secret-alice-key")
    assert ok

    # Wrong secret key rejected
    ok, reason = CanonicalBindingGuard.verify_signature_binding(sig, msg, "wrong-key")
    assert not ok
    assert "CANONICAL_BINDING_MISMATCH" in reason

    # Tampered message content rejected
    tampered_msg = Message(
        message_id=msg.message_id,
        payload="Authorize transfer of 1,000,000,000 INR",
        sender_id=msg.sender_id,
        receiver_id=msg.receiver_id,
        timestamp=msg.timestamp,
        digest=msg.digest,
    )
    ok, reason = CanonicalBindingGuard.verify_message_integrity(tampered_msg)
    assert not ok
    assert "MESSAGE_DIGEST_MISMATCH" in reason


def test_freshness_and_replay_detection():
    """Replay rejection must be 100% on identical nonces, and stale timestamps rejected."""
    guard = FreshnessGuard()
    policy = get_sample_policy()

    now = 1727700010.0
    session = Session(
        session_id="sess-replay-001",
        signer_id="alice@qds.bank",
        verifier_id="bob@qds.bank",
        created_at=1727700000.0,
        expires_at=1727703600.0,
    )
    guard.register_session(session)

    sig = get_sample_signature()
    sig.session_id = session.session_id
    sig.timestamp = now - 2.0  # 2 seconds old, within 10s skew
    sig.nonce = "unique-nonce-12345678"

    # First attempt: Fresh -> ACCEPT
    ok, reason, evidence = guard.check_freshness_and_replay(sig, policy, current_time=now)
    assert ok
    assert reason == "FRESHNESS_VERIFIED"
    assert evidence is None

    # Second attempt with SAME nonce: Replay -> REJECT (100% controlled corpus requirement)
    ok, reason, evidence = guard.check_freshness_and_replay(sig, policy, current_time=now + 1.0)
    assert not ok
    assert "REPLAY_DETECTED" in reason
    assert evidence is not None
    assert evidence["replay_detected"] == "true"
    assert evidence["nonce"] == "unique-nonce-12345678"


def test_stale_timestamp_and_clock_skew():
    """Signatures outside allowable clock skew are strictly rejected."""
    guard = FreshnessGuard()
    policy = get_sample_policy()  # max_clock_skew = 10.0s

    now = 1727700050.0
    session = Session(
        session_id="sess-skew-001",
        signer_id="alice@qds.bank",
        verifier_id="bob@qds.bank",
        created_at=1727700000.0,
        expires_at=1727703600.0,
    )
    guard.register_session(session)

    # Stale signature (30 seconds old)
    stale_sig = get_sample_signature()
    stale_sig.session_id = session.session_id
    stale_sig.timestamp = now - 30.0
    stale_sig.nonce = "nonce-stale-11111111"

    ok, reason, _ = guard.check_freshness_and_replay(stale_sig, policy, current_time=now)
    assert not ok
    assert "STALE_TIMESTAMP" in reason

    # Future signature (clock skew ahead by 25s)
    future_sig = get_sample_signature()
    future_sig.session_id = session.session_id
    future_sig.timestamp = now + 25.0
    future_sig.nonce = "nonce-future-22222222"

    ok, reason, _ = guard.check_freshness_and_replay(future_sig, policy, current_time=now)
    assert not ok
    assert "CLOCK_SKEW_FUTURE" in reason


def test_quarantined_session_rejected():
    """Sessions marked as quarantined fail closed."""
    guard = FreshnessGuard()
    policy = get_sample_policy()

    session = Session(
        session_id="sess-quarantined",
        signer_id="alice@qds.bank",
        verifier_id="bob@qds.bank",
        created_at=1727700000.0,
        expires_at=1727703600.0,
        is_quarantined=True,
    )
    guard.register_session(session)

    sig = get_sample_signature()
    sig.session_id = session.session_id
    sig.nonce = "nonce-fresh-33333333"

    ok, reason, _ = guard.check_freshness_and_replay(sig, policy, current_time=1727700005.0)
    assert not ok
    assert "QUARANTINED_SESSION" in reason


def test_rate_limiter():
    """Rate limiter enforces per-entity request quota."""
    limiter = RateLimiter(window_seconds=10.0)
    now = 100.0

    # 3 allowed
    for _ in range(3):
        allowed, count = limiter.is_allowed("verifier-1", limit=3, current_time=now)
        assert allowed

    # 4th rejected
    allowed, count = limiter.is_allowed("verifier-1", limit=3, current_time=now)
    assert not allowed
    assert count == 3

    # Different entity allowed
    allowed, count = limiter.is_allowed("verifier-2", limit=3, current_time=now)
    assert allowed
