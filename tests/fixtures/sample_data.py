"""
Sample fixtures and golden data for Eagle-Eye schema and contract tests.
"""
import time
from src.schemas import (
    Message,
    Identity,
    IdentityRole,
    PauliBasis,
    MeasurementRecord,
    MeasurementBatch,
    Signature,
    compute_canonical_binding,
    Session,
    Policy,
    Decision,
    Verdict,
    Incident,
    AttackType,
    IncidentSeverity,
    IncidentStatus,
)


def get_sample_message() -> Message:
    return Message.create(
        message_id="msg-golden-001",
        payload="Authorize quantum bank transfer of 100,000 INR to Account 987654321",
        sender_id="alice@qds.bank",
        receiver_id="bob@qds.bank",
        timestamp=1727700000.0,
    )


def get_sample_identity() -> Identity:
    return Identity(
        identity_id="alice@qds.bank",
        name="Alice Signature Node",
        role=IdentityRole.SIGNER,
        public_key_hex="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        is_authorized=True,
        permissions=["sign", "teleport"],
    )


def get_sample_session() -> Session:
    return Session(
        session_id="sess-2026-001",
        signer_id="alice@qds.bank",
        verifier_id="bob@qds.bank",
        created_at=1727700000.0,
        expires_at=1727703600.0,
        seen_nonces=["existing-nonce-1", "existing-nonce-2"],
        is_active=True,
    )


def get_sample_measurements() -> MeasurementBatch:
    records = [
        MeasurementRecord(
            qubit_index=0,
            basis=PauliBasis.Z,
            outcome=0,
            ideal_outcome=0,
            shots=1024,
            counts={"0": 1000, "1": 24},
        ),
        MeasurementRecord(
            qubit_index=1,
            basis=PauliBasis.X,
            outcome=1,
            ideal_outcome=1,
            shots=1024,
            counts={"0": 30, "1": 994},
        ),
        MeasurementRecord(
            qubit_index=2,
            basis=PauliBasis.Y,
            outcome=0,
            ideal_outcome=0,
            shots=1024,
            counts={"0": 985, "1": 39},
        ),
    ]
    return MeasurementBatch(
        batch_id="batch-001",
        session_id="sess-2026-001",
        records=records,
    )


def get_sample_signature() -> Signature:
    msg = get_sample_message()
    corrections = ["I", "X", "Z"]
    binding = compute_canonical_binding(
        signer_key="secret-alice-key",
        message_digest=msg.digest,
        session_id="sess-2026-001",
        nonce="fresh-nonce-9999",
        timestamp=1727700001.0,
        pauli_corrections=corrections,
    )
    return Signature(
        signature_id="sig-golden-001",
        message_id=msg.message_id,
        signer_identity="alice@qds.bank",
        session_id="sess-2026-001",
        nonce="fresh-nonce-9999",
        timestamp=1727700001.0,
        qubit_count=3,
        pauli_corrections=corrections,
        basis_announcements=["Z", "X", "Y"],
        canonical_binding=binding,
        measurements=get_sample_measurements(),
    )


def get_sample_policy() -> Policy:
    return Policy(
        policy_id="policy-default",
        version="1.0.0",
        max_qber_threshold=0.08,
        escalate_qber_threshold=0.045,
        max_tvd_threshold=0.15,
        confidence_level=0.95,
        max_clock_skew_seconds=10.0,
        min_qubit_sample_size=3,
        rate_limit_per_minute=60,
    )
