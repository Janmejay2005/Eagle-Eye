"""
Integration tests for the Dashboard REST API demonstrating the four primary attack paths.
Acceptance Gate 8: Evaluator demonstrates four attack paths.
"""
from fastapi.testclient import TestClient
import pytest

from src.dashboard.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_dashboard_ui_html(client):
    """Dashboard UI serves responsive zero-dependency HTML."""
    res = client.get("/")
    assert res.status_code == 200
    assert "EAGLE-EYE | Security Operator Dashboard" in res.text


def test_api_policy_endpoint(client):
    """Policy endpoint returns active policy and thresholds."""
    res = client.get("/api/policy")
    assert res.status_code == 200
    data = res.json()
    assert "max_qber_threshold" in data
    assert "version" in data


def test_demonstrate_attack_path_1_valid(client):
    """Demonstrate Path 1: Valid QDS signature -> ACCEPT."""
    res = client.post("/api/simulate/valid")
    assert res.status_code == 200
    data = res.json()
    assert data["scenario"] == "valid"
    assert data["decision"]["verdict"] == "ACCEPT"
    assert "SIGNATURE_AND_QUANTUM_METRICS_VERIFIED_SUCCESSFULLY" in data["decision"]["reasons"]


def test_demonstrate_attack_path_2_forgery(client):
    """Demonstrate Path 2: Forgery & Tampered Payload -> REJECT."""
    res = client.post("/api/simulate/forgery")
    assert res.status_code == 200
    data = res.json()
    assert data["scenario"] == "forgery"
    assert data["decision"]["verdict"] == "REJECT"
    assert "incident" in data
    assert data["incident"]["attack_type"] == "FORGERY"


def test_demonstrate_attack_path_3_replay(client):
    """Demonstrate Path 3: Replay & Nonce Reuse -> REJECT with evidence."""
    res = client.post("/api/simulate/replay")
    assert res.status_code == 200
    data = res.json()
    assert data["scenario"] == "replay"
    assert data["first_decision"]["verdict"] == "ACCEPT"
    assert data["replay_decision"]["verdict"] == "REJECT"
    assert "incident" in data
    assert data["incident"]["attack_type"] == "REPLAY"


def test_demonstrate_attack_path_4_channel(client):
    """Demonstrate Path 4: Channel Manipulation -> REJECT and QUARANTINE."""
    res = client.post("/api/simulate/channel")
    assert res.status_code == 200
    data = res.json()
    assert data["scenario"] == "channel"
    assert data["decision"]["verdict"] == "REJECT"
    assert "QUANTUM_SECURITY_BOUNDS_EXCEEDED" in data["decision"]["failed_checks"]
    assert "incident" in data
    assert data["incident"]["attack_type"] == "CHANNEL_MANIPULATION"


def test_demonstrate_path_5_self_healing_and_rollback(client):
    """Demonstrate Path 5: Incident response, shadow tests, signed deploy, and rollback."""
    res = client.post("/api/simulate/self-healing")
    assert res.status_code == 200
    data = res.json()
    assert data["shadow_tests_passed"] is True
    assert data["signature_present"] is True
    assert data["rollback_successful"] is True


def test_audit_trail_integrity(client):
    """Audit trail endpoint validates hash chain integrity across all events."""
    res = client.get("/api/audit")
    assert res.status_code == 200
    data = res.json()
    assert data["chain_integrity_valid"] is True
    assert data["total_events"] > 0
