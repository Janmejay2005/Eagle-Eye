"""
Projective measurement abstraction across Pauli X, Y, and Z bases with shot-based sampling.
"""
from __future__ import annotations

from typing import Optional, Tuple
import numpy as np

from src.schemas.measurement import PauliBasis, MeasurementRecord
from src.protocol.states import (
    KET_0,
    KET_1,
    KET_PLUS,
    KET_MINUS,
    KET_R,
    KET_L,
    normalize_state,
)


def compute_basis_probabilities(state: np.ndarray, basis: PauliBasis) -> Tuple[float, float]:
    """
    Computes exact Born-rule measurement probabilities (P(0), P(1)) for state in given basis.
    
    - Z basis: {|0>, |1>}
    - X basis: {|+> (0), |-> (1)}
    - Y basis: {|R> (0), |L> (1)}
    """
    psi = normalize_state(state)
    if basis == PauliBasis.Z:
        b0, b1 = KET_0, KET_1
    elif basis == PauliBasis.X:
        b0, b1 = KET_PLUS, KET_MINUS
    elif basis == PauliBasis.Y:
        b0, b1 = KET_R, KET_L
    else:
        raise ValueError(f"Unsupported Pauli basis: {basis}")

    p0 = float(np.abs(np.vdot(b0, psi)) ** 2)
    p1 = float(np.abs(np.vdot(b1, psi)) ** 2)

    total = p0 + p1
    if total > 0.0:
        p0 /= total
        p1 /= total
    else:
        p0, p1 = 0.5, 0.5

    if p0 < 1e-14:
        p0, p1 = 0.0, 1.0
    elif p1 < 1e-14:
        p0, p1 = 1.0, 0.0
    return float(p0), float(p1)


def measure_qubit(
    qubit_index: int,
    state: np.ndarray,
    basis: PauliBasis,
    ideal_state: Optional[np.ndarray] = None,
    shots: int = 1024,
    rng: Optional[np.random.Generator] = None,
) -> MeasurementRecord:
    """
    Performs projective Pauli measurement with shot-based sampling.
    """
    if rng is None:
        rng = np.random.default_rng()

    p0, p1 = compute_basis_probabilities(state, basis)

    # Shot-based sampling
    count_1 = int(rng.binomial(n=shots, p=p1))
    count_0 = shots - count_1

    # Single-shot / dominant outcome
    outcome = 1 if count_1 > count_0 else 0

    ideal_outcome: Optional[int] = None
    if ideal_state is not None:
        ip0, ip1 = compute_basis_probabilities(ideal_state, basis)
        ideal_outcome = 1 if ip1 > 0.5 else 0

    return MeasurementRecord(
        qubit_index=qubit_index,
        basis=basis,
        outcome=outcome,
        ideal_outcome=ideal_outcome,
        shots=shots,
        counts={"0": count_0, "1": count_1},
    )
