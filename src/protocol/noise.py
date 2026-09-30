"""
Quantum channel noise models for simulating channel degradation and disturbances.
"""
from __future__ import annotations

from typing import Optional
import numpy as np

from src.protocol.states import (
    I2,
    PAULI_X,
    PAULI_Y,
    PAULI_Z,
    normalize_state,
)


class QuantumNoiseChannel:
    """Configurable quantum noise channel with deterministic seed."""

    def __init__(
        self,
        depolarizing_rate: float = 0.0,
        bit_flip_rate: float = 0.0,
        phase_flip_rate: float = 0.0,
        loss_rate: float = 0.0,
        seed: Optional[int] = None,
    ):
        self.depolarizing_rate = float(depolarizing_rate)
        self.bit_flip_rate = float(bit_flip_rate)
        self.phase_flip_rate = float(phase_flip_rate)
        self.loss_rate = float(loss_rate)
        self.rng = np.random.default_rng(seed)

    def apply_to_state(self, state: np.ndarray) -> np.ndarray:
        """Applies channel noise stochastically to a single-qubit pure state."""
        state = normalize_state(state.copy())

        # Check for loss/erasure
        if self.loss_rate > 0.0 and self.rng.random() < self.loss_rate:
            # Replaced with random pure state (complete decoherence)
            theta = self.rng.uniform(0, np.pi)
            phi = self.rng.uniform(0, 2 * np.pi)
            return np.array([np.cos(theta / 2.0), np.exp(1.0j * phi) * np.sin(theta / 2.0)], dtype=np.complex128)

        # Depolarizing noise: with prob p, apply random Pauli X, Y, or Z with equal prob p/3
        if self.depolarizing_rate > 0.0 and self.rng.random() < self.depolarizing_rate:
            op_idx = self.rng.integers(0, 3)
            op = [PAULI_X, PAULI_Y, PAULI_Z][op_idx]
            state = op @ state

        # Bit flip (X)
        if self.bit_flip_rate > 0.0 and self.rng.random() < self.bit_flip_rate:
            state = PAULI_X @ state

        # Phase flip (Z)
        if self.phase_flip_rate > 0.0 and self.rng.random() < self.phase_flip_rate:
            state = PAULI_Z @ state

        return normalize_state(state)
