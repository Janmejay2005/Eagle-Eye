"""
End-to-end teleportation-based Quantum Digital Signature simulator.
"""
from __future__ import annotations

import time
from typing import List, Optional, Tuple
import numpy as np

from src.schemas import (
    Message,
    Signature,
    MeasurementRecord,
    MeasurementBatch,
    PauliBasis,
    compute_canonical_binding,
)
from src.protocol.states import (
    KET_0,
    KET_1,
    KET_PLUS,
    KET_MINUS,
    KET_R,
    KET_L,
)
from src.protocol.teleportation import teleport_qubit
from src.protocol.measurements import measure_qubit
from src.protocol.noise import QuantumNoiseChannel

# Alphabet of signature quantum states
SIGNATURE_STATES = {
    "0": KET_0,
    "1": KET_1,
    "+": KET_PLUS,
    "-": KET_MINUS,
    "R": KET_R,
    "L": KET_L,
}
STATE_BASES = {
    "0": PauliBasis.Z,
    "1": PauliBasis.Z,
    "+": PauliBasis.X,
    "-": PauliBasis.X,
    "R": PauliBasis.Y,
    "L": PauliBasis.Y,
}


class QDSSimulator:
    """Deterministic simulator for teleportation-based QDS protocols."""

    def __init__(self, seed: Optional[int] = None):
        self.seed = seed
        self.rng = np.random.default_rng(seed)

    def generate_honest_signature_and_measurements(
        self,
        message: Message,
        signer_key: str,
        session_id: str,
        nonce: str,
        qubit_count: int = 32,
        noise_channel: Optional[QuantumNoiseChannel] = None,
        shots_per_measurement: int = 1024,
        timestamp: Optional[float] = None,
    ) -> Tuple[Signature, MeasurementBatch]:
        """
        Simulates an honest signature generation, state teleportation, and verifier measurements.
        """
        keys = list(SIGNATURE_STATES.keys())
        # Generate random signature state keys using simulator RNG
        chosen_state_keys = [keys[int(idx)] for idx in self.rng.integers(0, len(keys), size=qubit_count)]

        pauli_corrections: List[str] = []
        measurement_records: List[MeasurementRecord] = []
        basis_announcements: List[str] = []

        now = message.timestamp if timestamp is None else timestamp

        for i, skey in enumerate(chosen_state_keys):
            ideal_state = SIGNATURE_STATES[skey]
            basis = STATE_BASES[skey]
            basis_announcements.append(basis.value)

            # Teleport state over quantum channel
            res = teleport_qubit(
                input_state=ideal_state,
                noise_channel=noise_channel,
                rng=self.rng,
            )
            pauli_corrections.append(res.pauli_correction)

            # Verifier measures reconstructed state in announced basis
            m_rec = measure_qubit(
                qubit_index=i,
                state=res.reconstructed_state,
                basis=basis,
                ideal_state=ideal_state,
                shots=shots_per_measurement,
                rng=self.rng,
            )
            measurement_records.append(m_rec)

        batch_id = f"batch-{nonce[:8]}-{int(now)}"
        batch = MeasurementBatch(
            batch_id=batch_id,
            session_id=session_id,
            records=measurement_records,
        )

        binding = compute_canonical_binding(
            signer_key=signer_key,
            message_digest=message.digest,
            session_id=session_id,
            nonce=nonce,
            timestamp=now,
            pauli_corrections=pauli_corrections,
        )

        sig = Signature(
            signature_id=f"sig-{nonce[:8]}",
            message_id=message.message_id,
            signer_identity=message.sender_id,
            session_id=session_id,
            nonce=nonce,
            timestamp=now,
            qubit_count=qubit_count,
            pauli_corrections=pauli_corrections,
            basis_announcements=basis_announcements,
            canonical_binding=binding,
            measurements=batch,
        )

        return sig, batch
