"""
Quantum teleportation protocol with Bell-State Measurement (BSM) and Pauli corrections.
"""
from __future__ import annotations

from typing import Optional, Tuple
import numpy as np

from src.protocol.states import (
    I2,
    PAULI_X,
    PAULI_Y,
    PAULI_Z,
    normalize_state,
    state_fidelity,
    PAULI_CORRECTIONS,
)
from src.protocol.noise import QuantumNoiseChannel


class TeleportationResult:
    """Holds artifacts of a single-qubit teleportation experiment."""

    def __init__(
        self,
        original_state: np.ndarray,
        bell_index: int,
        pauli_correction: str,
        received_state_before_correction: np.ndarray,
        reconstructed_state: np.ndarray,
        fidelity: float,
    ):
        self.original_state = original_state
        self.bell_index = bell_index
        self.pauli_correction = pauli_correction
        self.received_state_before_correction = received_state_before_correction
        self.reconstructed_state = reconstructed_state
        self.fidelity = fidelity


def apply_pauli_correction(state: np.ndarray, correction: str) -> np.ndarray:
    """Applies the prescribed Pauli correction operator to Bob's received qubit."""
    if correction == "I":
        res = state
    elif correction == "X":
        res = PAULI_X @ state
    elif correction == "Z":
        res = PAULI_Z @ state
    elif correction == "XZ":
        # Note: Z @ X restores (X @ Z) state exactly: (Z @ X) @ (X @ Z) = I
        res = (PAULI_Z @ PAULI_X) @ state
    else:
        raise ValueError(f"Unknown Pauli correction operator: {correction}")
    return normalize_state(res)


def teleport_qubit(
    input_state: np.ndarray,
    noise_channel: Optional[QuantumNoiseChannel] = None,
    rng: Optional[np.random.Generator] = None,
) -> TeleportationResult:
    """
    Executes quantum teleportation of a single signature qubit.
    
    1. Alice and Bob share Bell pair |Phi+>_23.
    2. Alice performs BSM on (qubit 1, qubit 2), yielding one of 4 Bell outcomes with equal prob 1/4.
    3. Bob's qubit 3 collapses into one of:
         - Bell outcome 0 (|Phi+>): |psi>   -> correction "I"
         - Bell outcome 1 (|Psi+>): X|psi>  -> correction "X"
         - Bell outcome 2 (|Phi->): Z|psi>  -> correction "Z"
         - Bell outcome 3 (|Psi->): XZ|psi> -> correction "XZ"
    4. Alice sends classical measurement outcome (m1, m2) to Bob.
    5. Bob receives qubit via quantum channel (subject to optional noise).
    6. Bob applies Pauli correction to reconstruct |psi>.
    """
    if rng is None:
        rng = np.random.default_rng()

    psi = normalize_state(input_state)

    # In ideal teleportation, each Bell outcome occurs with prob 0.25
    bell_idx = int(rng.integers(0, 4))
    correction = PAULI_CORRECTIONS[bell_idx]

    # Pre-correction state at Bob
    if bell_idx == 0:
        bob_raw = psi.copy()
    elif bell_idx == 1:
        bob_raw = PAULI_X @ psi
    elif bell_idx == 2:
        bob_raw = PAULI_Z @ psi
    elif bell_idx == 3:
        bob_raw = (PAULI_X @ PAULI_Z) @ psi
    else:
        bob_raw = psi.copy()

    bob_raw = normalize_state(bob_raw)

    # Quantum channel noise between Bell distribution / reception
    if noise_channel is not None:
        bob_received = noise_channel.apply_to_state(bob_raw)
    else:
        bob_received = bob_raw

    # Bob applies Pauli correction
    bob_final = apply_pauli_correction(bob_received, correction)
    fidelity = state_fidelity(psi, bob_final)

    return TeleportationResult(
        original_state=psi,
        bell_index=bell_idx,
        pauli_correction=correction,
        received_state_before_correction=bob_received,
        reconstructed_state=bob_final,
        fidelity=fidelity,
    )
