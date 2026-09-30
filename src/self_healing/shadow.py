"""
Shadow test runner executing regression testing on golden corpora prior to rule bundle deployment.
"""
from __future__ import annotations

from typing import Dict, List, Tuple
from src.schemas import Message, Policy, Session, Identity, IdentityRole, Verdict
from src.protocol import QDSSimulator, QuantumNoiseChannel
from src.guards import IdentityRegistry, FreshnessGuard
from src.decision.verifier import VerificationEngine
from src.attacks import ForgerySimulator, ReplaySimulator


class ShadowTestRunner:
    """Executes pre-deployment shadow evaluations on candidate policies."""

    def __init__(self, simulator_seed: int = 888):
        self.simulator = QDSSimulator(seed=simulator_seed)

    def run_regression_suite(self, candidate_policy: Policy) -> Tuple[bool, Dict[str, float]]:
        """
        Runs candidate policy against golden honest, forgery, and replay corpora.
        Target Gates:
        - Honest Acceptance >= 95% (FRR <= 5%)
        - Forgery Rejection >= 90% (FAR <= 10%)
        - Replay Rejection == 100%
        """
        registry = IdentityRegistry()
        alice = Identity(
            identity_id="alice@qds.bank",
            name="Alice",
            role=IdentityRole.SIGNER,
            public_key_hex="1122334455667788",
            is_authorized=True,
            permissions=["sign"],
        )
        bob = Identity(
            identity_id="bob@qds.bank",
            name="Bob",
            role=IdentityRole.VERIFIER,
            public_key_hex="8877665544332211",
            is_authorized=True,
            permissions=["verify"],
        )
        registry.register(alice, secret_key="alice-shadow-secret")
        registry.register(bob)

        # 1. Honest corpus evaluation (20 samples with honest channel noise ~2%)
        honest_accepted = 0
        honest_total = 20
        noise = QuantumNoiseChannel(depolarizing_rate=0.02, seed=100)

        for i in range(honest_total):
            ts = 1727700000.0 + i * 5
            guard = FreshnessGuard()
            sess = Session(
                session_id=f"sess-h-{i}",
                signer_id=alice.identity_id,
                verifier_id=bob.identity_id,
                created_at=ts - 10,
                expires_at=ts + 3600,
            )
            guard.register_session(sess)
            engine = VerificationEngine(registry=registry, freshness_guard=guard)

            msg = Message.create(f"msg-h-{i}", f"Honest payload {i}", alice.identity_id, bob.identity_id, timestamp=ts)
            sig, _ = self.simulator.generate_honest_signature_and_measurements(
                message=msg,
                signer_key="alice-shadow-secret",
                session_id=sess.session_id,
                nonce=f"nonce-h-{i:04d}",
                qubit_count=32,
                noise_channel=noise,
                timestamp=ts,
            )
            dec = engine.verify(msg, sig, bob.identity_id, candidate_policy, current_time=ts)
            if dec.verdict in (Verdict.ACCEPT, Verdict.ESCALATE):
                honest_accepted += 1

        honest_acc_rate = honest_accepted / honest_total

        # 2. Forgery corpus evaluation (15 samples of quantum/message tampered signatures)
        forgery_rejected = 0
        forgery_total = 15

        for i in range(forgery_total):
            ts = 1727710000.0 + i * 5
            guard = FreshnessGuard()
            sess = Session(
                session_id=f"sess-f-{i}",
                signer_id=alice.identity_id,
                verifier_id=bob.identity_id,
                created_at=ts - 10,
                expires_at=ts + 3600,
            )
            guard.register_session(sess)
            engine = VerificationEngine(registry=registry, freshness_guard=guard)

            msg = Message.create(f"msg-f-{i}", f"Legit payload {i}", alice.identity_id, bob.identity_id, timestamp=ts)
            sig, _ = self.simulator.generate_honest_signature_and_measurements(
                message=msg,
                signer_key="alice-shadow-secret",
                session_id=sess.session_id,
                nonce=f"nonce-f-{i:04d}",
                qubit_count=32,
                timestamp=ts,
            )
            # Tamper measurements
            tampered_sig = ForgerySimulator.tamper_quantum_measurements(sig, flip_fraction=0.35, seed=200 + i)
            dec = engine.verify(msg, tampered_sig, bob.identity_id, candidate_policy, current_time=ts)
            if dec.verdict == Verdict.REJECT:
                forgery_rejected += 1

        forgery_rej_rate = forgery_rejected / forgery_total

        # 3. Replay corpus evaluation (10 replay attempts)
        replay_rejected = 0
        replay_total = 10

        for i in range(replay_total):
            ts = 1727720000.0 + i * 5
            guard = FreshnessGuard()
            sess = Session(
                session_id=f"sess-r-{i}",
                signer_id=alice.identity_id,
                verifier_id=bob.identity_id,
                created_at=ts - 10,
                expires_at=ts + 3600,
            )
            guard.register_session(sess)
            engine = VerificationEngine(registry=registry, freshness_guard=guard)

            msg = Message.create(f"msg-r-{i}", f"Replay payload {i}", alice.identity_id, bob.identity_id, timestamp=ts)
            sig, _ = self.simulator.generate_honest_signature_and_measurements(
                message=msg,
                signer_key="alice-shadow-secret",
                session_id=sess.session_id,
                nonce=f"nonce-r-{i:04d}",
                qubit_count=32,
                timestamp=ts,
            )
            # First verification consumes nonce
            engine.verify(msg, sig, bob.identity_id, candidate_policy, current_time=ts)
            # Replay attempt
            replayed_sig = ReplaySimulator.create_identical_replay(sig)
            dec_rep = engine.verify(msg, replayed_sig, bob.identity_id, candidate_policy, current_time=ts + 1.0)
            if dec_rep.verdict == Verdict.REJECT:
                replay_rejected += 1

        replay_rej_rate = replay_rejected / replay_total

        metrics = {
            "honest_acceptance_rate": honest_acc_rate,
            "forgery_rejection_rate": forgery_rej_rate,
            "replay_rejection_rate": replay_rej_rate,
        }

        # Gate criteria
        passed = (honest_acc_rate >= 0.95) and (forgery_rej_rate >= 0.90) and (replay_rej_rate == 1.0)
        return passed, metrics
