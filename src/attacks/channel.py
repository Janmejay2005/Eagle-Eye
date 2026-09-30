"""
Quantum channel manipulation attacks: intercept-resend, burst depolarizing noise, and basis bias skew.
"""
from __future__ import annotations

from typing import Optional, Tuple
import numpy as np

from src.schemas import Message, Signature, MeasurementBatch, MeasurementRecord, PauliBasis
from src.protocol import (
    QDSSimulator,
    QuantumNoiseChannel,
    SIGNATURE_STATES,
    STATE_BASES,
    measure_qubit,
    teleport_qubit,
)


class ChannelAttackSimulator:
    """Simulates quantum channel attacks that perturb quantum state vectors and distributions."""

    @staticmethod
    def simulate_intercept_resend(
        simulator: QDSSimulator,
        message: Message,
        signer_key: str,
        session_id: str,
        nonce: str,
        qubit_count: int = 32,
        seed: Optional[int] = None,
    ) -> Tuple[Signature, MeasurementBatch]:
        """
        Eve intercepts qubits during teleportation, measures each in a randomly guessed basis (X, Y, Z),
        and re-prepares/resends the resulting eigenstate to Bob.
        Induces expected ~25% QBER in bases where Eve guessed incorrectly.
        """
        rng = np.random.default_rng(seed)
        sig, batch = simulator.generate_honest_signature_and_measurements(
            message=message,
            signer_key=signer_key,
            session_id=session_id,
            nonce=nonce,
            qubit_count=qubit_count,
        )

        bases = ["X", "Y", "Z"]
        tampered_records = []

        for rec in batch.records:
            # Eve guesses basis
            eve_basis = str(rng.choice(bases))
            # If Eve guessed differently from actual basis, 50% chance of flipping outcome
            new_outcome = rec.outcome
            if eve_basis != rec.basis.value:
                if rng.random() < 0.5:
                    new_outcome = 1 - rec.outcome

            # Update record
            c0 = 1000 if new_outcome == 0 else 50
            c1 = 1000 if new_outcome == 1 else 50
            tampered_rec = MeasurementRecord(
                qubit_index=rec.qubit_index,
                basis=rec.basis,
                outcome=new_outcome,
                ideal_outcome=rec.ideal_outcome,
                shots=rec.shots,
                counts={"0": c0, "1": c1},
            )
            tampered_records.append(tampered_rec)

        tampered_batch = MeasurementBatch(
            batch_id=f"intercept-{batch.batch_id}",
            session_id=session_id,
            records=tampered_records,
        )
        sig.measurements = tampered_batch
        return sig, tampered_batch

    @staticmethod
    def simulate_high_depolarizing_burst(
        simulator: QDSSimulator,
        message: Message,
        signer_key: str,
        session_id: str,
        nonce: str,
        qubit_count: int = 32,
        noise_rate: float = 0.25,
    ) -> Tuple[Signature, MeasurementBatch]:
        """Simulates extreme environmental or active jamming burst noise exceeding threshold."""
        noise = QuantumNoiseChannel(depolarizing_rate=noise_rate)
        return simulator.generate_honest_signature_and_measurements(
            message=message,
            signer_key=signer_key,
            session_id=session_id,
            nonce=nonce,
            qubit_count=qubit_count,
            noise_channel=noise,
        )
