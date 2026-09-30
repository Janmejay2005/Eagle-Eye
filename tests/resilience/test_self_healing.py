"""
Resilience and regression testing for Controlled Self-Healing:
Proposals, shadow tests, cryptographic signing, approval gates, and rollback.

Acceptance Gate 7: No unapproved update; bad update rolls back.
"""
import pytest

from src.schemas import Policy, Identity, IdentityRole
from src.self_healing import (
    SelfHealingEngine,
    UnapprovedUpdateError,
    ShadowRegressionError,
    generate_ed25519_keypair,
)


@pytest.fixture
def self_healing_env():
    priv_b64, pub_b64 = generate_ed25519_keypair()
    admin = Identity(
        identity_id="admin@qds.bank",
        name="Chief Security Officer",
        role=IdentityRole.ADMIN,
        public_key_hex=pub_b64,
        is_authorized=True,
        permissions=["admin", "approve_policy"],
    )

    initial_policy = Policy(
        policy_id="policy-prod",
        version="1.0.0",
        max_qber_threshold=0.08,
        escalate_qber_threshold=0.045,
        max_tvd_threshold=0.15,
        max_clock_skew_seconds=10.0,
    )

    engine = SelfHealingEngine(initial_policy)
    return {
        "engine": engine,
        "admin": admin,
        "admin_priv": priv_b64,
        "admin_pub": pub_b64,
        "initial_policy": initial_policy,
    }


def test_no_unapproved_update_without_shadow_and_signature(self_healing_env):
    """Rule bundles without shadow testing or valid signature are strictly rejected."""
    env = self_healing_env
    engine = env["engine"]

    candidate = Policy(
        policy_id="policy-prod",
        version="1.0.1",
        max_qber_threshold=0.075,  # Tightened threshold
        escalate_qber_threshold=0.040,
    )
    bundle = engine.propose_update(candidate, change_rationale="Tighten QBER in response to channel drift")

    # Attempt to apply unapproved bundle directly -> raises UnapprovedUpdateError
    with pytest.raises(UnapprovedUpdateError):
        engine.apply_update(bundle.bundle_id, env["admin_pub"])


def test_approval_fails_if_shadow_not_run(self_healing_env):
    """Approval cannot be granted without verified shadow test execution."""
    env = self_healing_env
    engine = env["engine"]

    candidate = Policy(version="1.0.2", max_qber_threshold=0.07)
    bundle = engine.propose_update(candidate, change_rationale="Tighten bounds")

    with pytest.raises(ShadowRegressionError):
        engine.approve_and_sign(bundle.bundle_id, env["admin"], env["admin_priv"])


def test_bad_update_fails_shadow_testing(self_healing_env):
    """A bad policy that causes regressions (e.g. ultra-strict thresholds rejecting honest traffic) fails shadow tests."""
    env = self_healing_env
    engine = env["engine"]

    bad_policy = Policy(
        version="0.9.0-bad",
        max_qber_threshold=0.005,  # Ultra-strict threshold that rejects honest 2% noise
        escalate_qber_threshold=0.001,
        allow_escalate_on_honest_noise=False,
    )
    bundle = engine.propose_update(bad_policy, change_rationale="Overly strict policy causing honest user rejections")

    passed, metrics = engine.run_shadow_tests(bundle.bundle_id)
    assert not passed
    assert metrics["honest_acceptance_rate"] < 0.95  # Honest users blocked!


def test_successful_approved_update_lifecycle_and_rollback(self_healing_env):
    """Full lifecycle: Incident -> Proposal -> Shadow Test -> Approval -> Apply -> Rollback."""
    env = self_healing_env
    engine = env["engine"]

    # 1. Propose calibrated update
    valid_candidate = Policy(
        policy_id="policy-prod",
        version="1.1.0",
        max_qber_threshold=0.075,
        escalate_qber_threshold=0.040,
        max_tvd_threshold=0.14,
        max_clock_skew_seconds=8.0,
    )
    bundle = engine.propose_update(
        valid_candidate,
        change_rationale="Calibrated noise baseline following incident INC-2026-004",
        incident_id="INC-2026-004",
    )

    # 2. Run shadow tests
    passed, metrics = engine.run_shadow_tests(bundle.bundle_id)
    assert passed
    assert metrics["honest_acceptance_rate"] >= 0.95
    assert metrics["replay_rejection_rate"] == 1.0

    # 3. Cryptographically sign and approve
    engine.approve_and_sign(bundle.bundle_id, env["admin"], env["admin_priv"])
    assert bundle.ed25519_signature is not None

    # 4. Deploy update
    ckpt_id = engine.apply_update(bundle.bundle_id, env["admin_pub"])
    assert engine.active_policy.version == "1.1.0"
    assert engine.active_policy.max_clock_skew_seconds == 8.0

    # 5. Rollback demonstration
    restored = engine.rollback(ckpt_id)
    assert restored.version == "1.0.0"
    assert restored.max_clock_skew_seconds == 10.0
    assert engine.active_policy.version == "1.0.0"
