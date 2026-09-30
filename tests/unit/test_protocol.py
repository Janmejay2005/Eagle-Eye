"""
Unit tests for Quantum Protocol simulation: Bell states, teleportation, Pauli corrections,
projective measurements, noise channels, and deterministic reproducibility.

Acceptance Gate 2: Known states match expected distributions within tolerance.
"""
import numpy as np
import pytest

from src.protocol import (
    BELL_BASIS,
    BELL_PHI_PLUS,
    BELL_PHI_MINUS,
    BELL_PSI_PLUS,
    BELL_PSI_MINUS,
    KET_0,
    KET_1,
    KET_PLUS,
    KET_MINUS,
    KET_R,
    KET_L,
    QuantumNoiseChannel,
    teleport_qubit,
    apply_pauli_correction,
    compute_basis_probabilities,
    measure_qubit,
    QDSSimulator,
    SIGNATURE_STATES,
    STATE_BASES,
)
from src.schemas import PauliBasis, Message


def test_bell_states_orthonormality():
    """All 4 Bell states must form an orthonormal basis in C^4."""
    for i in range(4):
        for j in range(4):
            inner = np.vdot(BELL_BASIS[i], BELL_BASIS[j])
            expected = 1.0 if i == j else 0.0
            assert np.isclose(inner, expected, atol=1e-10), f"Bell inner product fail at ({i},{j}): {inner}"


def test_teleportation_noiseless_fidelity():
    """Teleportation without noise must achieve fidelity 1.0 across all signature basis states."""
    rng = np.random.default_rng(42)
    test_states = [KET_0, KET_1, KET_PLUS, KET_MINUS, KET_R, KET_L]

    for state in test_states:
        for _ in range(10):
            res = teleport_qubit(state, noise_channel=None, rng=rng)
            assert np.isclose(res.fidelity, 1.0, atol=1e-9), f"Fidelity was {res.fidelity}"
            assert res.bell_index in (0, 1, 2, 3)
            assert res.pauli_correction in ("I", "X", "Z", "XZ")


def test_projective_measurements_born_rule():
    """Projective measurements must match theoretical Born-rule probabilities."""
    p0, p1 = compute_basis_probabilities(KET_0, PauliBasis.Z)
    assert np.isclose(p0, 1.0) and np.isclose(p1, 0.0)

    p0, p1 = compute_basis_probabilities(KET_1, PauliBasis.Z)
    assert np.isclose(p0, 0.0) and np.isclose(p1, 1.0)

    p0, p1 = compute_basis_probabilities(KET_PLUS, PauliBasis.X)
    assert np.isclose(p0, 1.0) and np.isclose(p1, 0.0)

    p0, p1 = compute_basis_probabilities(KET_MINUS, PauliBasis.X)
    assert np.isclose(p0, 0.0) and np.isclose(p1, 1.0)

    p0, p1 = compute_basis_probabilities(KET_R, PauliBasis.Y)
    assert np.isclose(p0, 1.0) and np.isclose(p1, 0.0)

    p0, p1 = compute_basis_probabilities(KET_L, PauliBasis.Y)
    assert np.isclose(p0, 0.0) and np.isclose(p1, 1.0)

    # Incompatible / conjugate basis yields 50/50 distribution
    p0_x, p1_x = compute_basis_probabilities(KET_0, PauliBasis.X)
    assert np.isclose(p0_x, 0.5, atol=1e-9)
    assert np.isclose(p1_x, 0.5, atol=1e-9)

    p0_y, p1_y = compute_basis_probabilities(KET_0, PauliBasis.Y)
    assert np.isclose(p0_y, 0.5, atol=1e-9)
    assert np.isclose(p1_y, 0.5, atol=1e-9)


def test_shot_sampling_distribution_tolerance():
    """Shot-based sampling must fall within statistical binomial tolerance."""
    rng = np.random.default_rng(12345)
    shots = 5000
    rec = measure_qubit(
        qubit_index=0,
        state=KET_0,
        basis=PauliBasis.X,
        shots=shots,
        rng=rng,
    )
    # For p = 0.5 with 5000 shots, 3*sigma = 3 * sqrt(5000 * 0.25) ~ 106 shots
    diff = abs(rec.counts["0"] - 2500)
    assert diff < 150, f"Observed count {rec.counts['0']} outside tolerance"


def test_noise_channel_fidelity_degradation():
    """High depolarizing noise must degrade teleportation fidelity."""
    rng = np.random.default_rng(999)
    noisy_channel = QuantumNoiseChannel(depolarizing_rate=0.5, seed=999)
    fidelities = []
    for _ in range(50):
        res = teleport_qubit(KET_0, noise_channel=noisy_channel, rng=rng)
        fidelities.append(res.fidelity)

    mean_fid = np.mean(fidelities)
    # Depolarizing noise should significantly reduce mean fidelity below 1.0
    assert mean_fid < 0.90, f"Expected degraded fidelity, got mean {mean_fid}"


def test_simulator_deterministic_reproducibility():
    """Identical seeds must produce identical signatures and measurements."""
    msg = Message.create("msg-seed-test", "Secret Transaction", "alice", "bob", timestamp=1727700000.0)

    sim1 = QDSSimulator(seed=4242)
    sig1, batch1 = sim1.generate_honest_signature_and_measurements(
        message=msg,
        signer_key="secret-key",
        session_id="sess-seed",
        nonce="nonce-seed-12345",
        qubit_count=16,
    )

    sim2 = QDSSimulator(seed=4242)
    sig2, batch2 = sim2.generate_honest_signature_and_measurements(
        message=msg,
        signer_key="secret-key",
        session_id="sess-seed",
        nonce="nonce-seed-12345",
        qubit_count=16,
    )

    assert sig1.pauli_corrections == sig2.pauli_corrections
    assert sig1.basis_announcements == sig2.basis_announcements
    assert [r.outcome for r in batch1.records] == [r.outcome for r in batch2.records]
    assert [r.counts for r in batch1.records] == [r.counts for r in batch2.records]
