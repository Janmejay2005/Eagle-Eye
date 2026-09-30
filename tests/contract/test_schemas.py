"""
Contract and validation tests for Eagle-Eye schemas.
Acceptance Gate 1: Fixtures validate; invalid inputs rejected.
"""
import pytest
from pydantic import ValidationError

from src.schemas import (
    Message,
    Identity,
    IdentityRole,
    PauliBasis,
    MeasurementRecord,
    MeasurementBatch,
    Signature,
    Session,
    Policy,
    Decision,
    Verdict,
    Incident,
    AttackType,
    IncidentSeverity,
    IncidentStatus,
)
from tests.fixtures.sample_data import (
    get_sample_message,
    get_sample_identity,
    get_sample_session,
    get_sample_measurements,
    get_sample_signature,
    get_sample_policy,
)


def test_valid_fixtures_validate():
    """Verify all golden fixtures instantiate and validate cleanly."""
    msg = get_sample_message()
    assert msg.verify_integrity() is True

    ident = get_sample_identity()
    assert ident.has_permission("sign") is True
    assert ident.has_permission("audit") is False

    sess = get_sample_session()
    assert sess.is_expired(1727701000.0) is False
    assert sess.register_nonce("brand-new-nonce") is True
    assert sess.register_nonce("existing-nonce-1") is False

    meas = get_sample_measurements()
    assert meas.sample_size == 3
    assert meas.error_count == 0

    sig = get_sample_signature()
    assert sig.verify_binding("secret-alice-key", msg.digest) is True
    assert sig.verify_binding("wrong-key", msg.digest) is False

    pol = get_sample_policy()
    assert pol.version == "1.0.0"

    dec = Decision(
        decision_id="dec-001",
        request_id="req-001",
        signature_id=sig.signature_id,
        message_id=msg.message_id,
        verdict=Verdict.ACCEPT,
        reasons=["VERIFIED_SUCCESS"],
        policy_version=pol.version,
    )
    dec.seal(previous_hash="0000000000000000000000000000000000000000000000000000000000000000")
    assert dec.event_hash is not None

    inc = Incident(
        incident_id="inc-001",
        attack_type=AttackType.FORGERY,
        severity=IncidentSeverity.CRITICAL,
        decision_id=dec.decision_id,
    )
    assert inc.status == IncidentStatus.DETECTED


def test_invalid_message_tampered_digest():
    """Tampering with message payload causes verify_integrity to return False."""
    msg = get_sample_message()
    tampered_msg = Message(
        message_id=msg.message_id,
        payload="Authorize fraudulent transfer of 999,999 INR",
        sender_id=msg.sender_id,
        receiver_id=msg.receiver_id,
        timestamp=msg.timestamp,
        digest=msg.digest,  # old digest with new payload
    )
    assert tampered_msg.verify_integrity() is False


def test_invalid_measurement_counts_rejected():
    """Measurement counts must only have keys '0' or '1'."""
    with pytest.raises(ValidationError):
        MeasurementRecord(
            qubit_index=0,
            basis=PauliBasis.Z,
            outcome=0,
            shots=100,
            counts={"0": 90, "2": 10},  # Invalid key '2'
        )


def test_invalid_outcome_bound_rejected():
    """Projective outcome must be 0 or 1."""
    with pytest.raises(ValidationError):
        MeasurementRecord(
            qubit_index=0,
            basis=PauliBasis.Z,
            outcome=2,  # Invalid outcome
        )


def test_invalid_policy_thresholds_rejected():
    """Policy bounds must satisfy mathematical probabilities in [0.0, 1.0]."""
    with pytest.raises(ValidationError):
        Policy(max_qber_threshold=1.5)  # > 1.0

    with pytest.raises(ValidationError):
        Policy(confidence_level=0.4)  # < 0.5


def test_invalid_signature_length():
    """Signature nonce must have at least 8 characters."""
    msg = get_sample_message()
    with pytest.raises(ValidationError):
        Signature(
            signature_id="sig-bad",
            message_id=msg.message_id,
            signer_identity="alice",
            session_id="sess-1",
            nonce="short",  # < 8 chars
            timestamp=123456.0,
            qubit_count=1,
            pauli_corrections=["I"],
            basis_announcements=["Z"],
            canonical_binding="bad",
        )
