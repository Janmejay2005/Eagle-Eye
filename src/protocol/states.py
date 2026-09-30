"""
Quantum state representations, Pauli matrices, and Bell states for QDS simulation.
"""
from __future__ import annotations

import numpy as np

# Pauli matrices
I2 = np.eye(2, dtype=np.complex128)
PAULI_X = np.array([[0.0, 1.0], [1.0, 0.0]], dtype=np.complex128)
PAULI_Y = np.array([[0.0, -1.0j], [1.0j, 0.0]], dtype=np.complex128)
PAULI_Z = np.array([[1.0, 0.0], [0.0, -1.0]], dtype=np.complex128)

# Computational basis states
KET_0 = np.array([1.0, 0.0], dtype=np.complex128)
KET_1 = np.array([0.0, 1.0], dtype=np.complex128)

# Hadamard (X) basis states
KET_PLUS = (KET_0 + KET_1) / np.sqrt(2.0)
KET_MINUS = (KET_0 - KET_1) / np.sqrt(2.0)

# Circular (Y) basis states
KET_R = (KET_0 + 1.0j * KET_1) / np.sqrt(2.0)
KET_L = (KET_0 - 1.0j * KET_1) / np.sqrt(2.0)

# Bell states (2-qubit state vectors in C^4)
# |Phi+> = (|00> + |11>) / sqrt(2)
BELL_PHI_PLUS = np.array([1.0, 0.0, 0.0, 1.0], dtype=np.complex128) / np.sqrt(2.0)
# |Phi-> = (|00> - |11>) / sqrt(2)
BELL_PHI_MINUS = np.array([1.0, 0.0, 0.0, -1.0], dtype=np.complex128) / np.sqrt(2.0)
# |Psi+> = (|01> + |10>) / sqrt(2)
BELL_PSI_PLUS = np.array([0.0, 1.0, 1.0, 0.0], dtype=np.complex128) / np.sqrt(2.0)
# |Psi-> = (|01> - |10>) / sqrt(2)
BELL_PSI_MINUS = np.array([0.0, 1.0, -1.0, 0.0], dtype=np.complex128) / np.sqrt(2.0)

BELL_BASIS = [BELL_PHI_PLUS, BELL_PSI_PLUS, BELL_PHI_MINUS, BELL_PSI_MINUS]
BELL_NAMES = ["Phi+", "Psi+", "Phi-", "Psi-"]
PAULI_CORRECTIONS = ["I", "X", "Z", "XZ"]


def normalize_state(psi: np.ndarray) -> np.ndarray:
    """Normalizes a quantum state vector to unit norm."""
    norm = np.linalg.norm(psi)
    if norm < 1e-12:
        raise ValueError("State vector norm too close to zero.")
    return psi / norm


def state_fidelity(psi: np.ndarray, phi: np.ndarray) -> float:
    """Calculates fidelity |<psi|phi>|^2 between pure state vectors."""
    psi_n = normalize_state(psi)
    phi_n = normalize_state(phi)
    overlap = np.vdot(psi_n, phi_n)
    return float(np.abs(overlap) ** 2)
