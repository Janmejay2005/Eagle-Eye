"""
Eagle-Eye Security Operator Dashboard & Verification Service.
Provides REST APIs and an interactive offline operator console for demonstrating QDS threat detection.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from src.schemas import (
    Message,
    Signature,
    Policy,
    Decision,
    Verdict,
    Identity,
    IdentityRole,
    Session,
    Incident,
    AttackType,
    IncidentSeverity,
    IncidentStatus,
)
from src.protocol import QDSSimulator, QuantumNoiseChannel
from src.guards import IdentityRegistry, FreshnessGuard, RateLimiter
from src.decision.verifier import VerificationEngine
from src.decision.audit_ledger import AuditLedger
from src.attacks import (
    ForgerySimulator,
    ImpersonationSimulator,
    ReplaySimulator,
    ChannelAttackSimulator,
)
from src.self_healing import (
    SelfHealingEngine,
    generate_ed25519_keypair,
)

app = FastAPI(
    title="Eagle-Eye QDS Threat Detection Console",
    description="Quantum-inspired cyber-threat detection for teleportation-based QDS (SIH PS 26141)",
    version="0.1.0",
)

# Global State Container
class SystemState:
    def __init__(self):
        self.registry = IdentityRegistry()
        self.freshness_guard = FreshnessGuard()
        self.rate_limiter = RateLimiter(window_seconds=60.0)
        self.audit_ledger = AuditLedger()
        self.simulator = QDSSimulator(seed=42)

        # Admin keypair for self-healing
        self.admin_priv_b64, self.admin_pub_b64 = generate_ed25519_keypair()
        self.admin_identity = Identity(
            identity_id="admin@qds.bank",
            name="Eagle-Eye Security Admin",
            role=IdentityRole.ADMIN,
            public_key_hex=self.admin_pub_b64,
            is_authorized=True,
            permissions=["admin", "verify"],
        )
        self.registry.register(self.admin_identity)

        # Authorized Signer Alice
        self.alice = Identity(
            identity_id="alice@qds.bank",
            name="Alice Signer Node",
            role=IdentityRole.SIGNER,
            public_key_hex="alice-pub-key-hex-0001",
            is_authorized=True,
            permissions=["sign"],
        )
        self.registry.register(self.alice, secret_key="alice-hsm-secret-key-12345")

        # Authorized Verifier Bob
        self.bob = Identity(
            identity_id="bob@qds.bank",
            name="Bob Verifier Node",
            role=IdentityRole.VERIFIER,
            public_key_hex="bob-pub-key-hex-0002",
            is_authorized=True,
            permissions=["verify"],
        )
        self.registry.register(self.bob)

        # Default Policy
        self.default_policy = Policy(
            policy_id="policy-production-v1",
            version="1.0.0",
            max_qber_threshold=0.08,
            escalate_qber_threshold=0.045,
            max_tvd_threshold=0.15,
            confidence_level=0.95,
            max_clock_skew_seconds=10.0,
            min_qubit_sample_size=16,
            rate_limit_per_minute=120,
        )

        self.self_healing = SelfHealingEngine(self.default_policy)
        self.engine = VerificationEngine(
            registry=self.registry,
            freshness_guard=self.freshness_guard,
            rate_limiter=self.rate_limiter,
            audit_ledger=self.audit_ledger,
        )

        # Session
        self.active_session = Session(
            session_id="session-live-001",
            signer_id="alice@qds.bank",
            verifier_id="bob@qds.bank",
            created_at=time.time(),
            expires_at=time.time() + 86400,
        )
        self.freshness_guard.register_session(self.active_session)
        self.incidents: List[Incident] = []


state = SystemState()


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "policy_version": state.self_healing.active_policy.version,
        "total_audit_records": len(state.audit_ledger.chain),
        "total_incidents": len(state.incidents),
    }


@app.get("/api/audit")
def get_audit_trail():
    chain = state.audit_ledger.chain
    is_valid, msg = state.audit_ledger.verify_chain_integrity()
    return {
        "chain_integrity_valid": is_valid,
        "integrity_message": msg,
        "total_events": len(chain),
        "records": [d.model_dump() for d in chain],
    }


@app.get("/api/policy")
def get_policy():
    return state.self_healing.active_policy.model_dump()


@app.get("/api/incidents")
def get_incidents():
    return [inc.model_dump() for inc in state.incidents]


@app.post("/api/simulate/{scenario}")
def simulate_attack_path(scenario: str):
    """
    Executes one of the primary demonstration paths:
    1. 'valid' -> Valid signature under ideal conditions (ACCEPT)
    2. 'forgery' -> Classical payload or quantum state tampering (REJECT)
    3. 'replay' -> Captured valid packet replayed with same nonce (REJECT)
    4. 'channel' -> Quantum channel intercept-resend attack (REJECT + QUARANTINE)
    5. 'self-healing' -> Demonstrate incident proposal, shadow testing, signed apply, and rollback
    """
    now = time.time()
    policy = state.self_healing.active_policy

    if scenario == "valid":
        msg = Message.create(
            message_id=f"msg-val-{uuid.uuid4().hex[:6]}",
            payload="Authorize 15,000 INR wire to Vendor",
            sender_id="alice@qds.bank",
            receiver_id="bob@qds.bank",
            timestamp=now,
        )
        sig, _ = state.simulator.generate_honest_signature_and_measurements(
            message=msg,
            signer_key="alice-hsm-secret-key-12345",
            session_id=state.active_session.session_id,
            nonce=f"nonce-val-{uuid.uuid4().hex[:8]}",
            qubit_count=32,
            timestamp=now,
        )
        dec = state.engine.verify(msg, sig, "bob@qds.bank", policy, current_time=now)
        return {"scenario": scenario, "decision": dec.model_dump()}

    elif scenario == "forgery":
        msg = Message.create(
            message_id=f"msg-forg-{uuid.uuid4().hex[:6]}",
            payload="Legitimate payment 5,000 INR",
            sender_id="alice@qds.bank",
            receiver_id="bob@qds.bank",
            timestamp=now,
        )
        sig, _ = state.simulator.generate_honest_signature_and_measurements(
            message=msg,
            signer_key="alice-hsm-secret-key-12345",
            session_id=state.active_session.session_id,
            nonce=f"nonce-forg-{uuid.uuid4().hex[:8]}",
            qubit_count=32,
            timestamp=now,
        )
        # Tamper payload
        tampered_msg = ForgerySimulator.tamper_message_payload(msg, "Fraudulent transfer 5,000,000 INR to Eve")
        dec = state.engine.verify(tampered_msg, sig, "bob@qds.bank", policy, current_time=now)

        # Record Incident
        inc = Incident(
            incident_id=f"INC-{uuid.uuid4().hex[:6]}",
            timestamp=now,
            attack_type=AttackType.FORGERY,
            severity=IncidentSeverity.CRITICAL,
            decision_id=dec.decision_id,
            evidence={"tampered_payload": tampered_msg.payload, "original_digest": msg.digest},
        )
        state.incidents.append(inc)
        return {"scenario": scenario, "decision": dec.model_dump(), "incident": inc.model_dump()}

    elif scenario == "replay":
        msg = Message.create(
            message_id=f"msg-rep-{uuid.uuid4().hex[:6]}",
            payload="One-time payment voucher 1,000 INR",
            sender_id="alice@qds.bank",
            receiver_id="bob@qds.bank",
            timestamp=now,
        )
        nonce = f"nonce-replay-{uuid.uuid4().hex[:8]}"
        sig, _ = state.simulator.generate_honest_signature_and_measurements(
            message=msg,
            signer_key="alice-hsm-secret-key-12345",
            session_id=state.active_session.session_id,
            nonce=nonce,
            qubit_count=32,
            timestamp=now,
        )
        # First verification succeeds
        dec1 = state.engine.verify(msg, sig, "bob@qds.bank", policy, current_time=now)

        # Replay attempt with same nonce
        replayed_sig = ReplaySimulator.create_identical_replay(sig)
        dec2 = state.engine.verify(msg, replayed_sig, "bob@qds.bank", policy, current_time=now + 0.5)

        inc = Incident(
            incident_id=f"INC-{uuid.uuid4().hex[:6]}",
            timestamp=now + 0.5,
            attack_type=AttackType.REPLAY,
            severity=IncidentSeverity.HIGH,
            decision_id=dec2.decision_id,
            evidence={"replayed_nonce": nonce, "first_decision": dec1.decision_id},
        )
        state.incidents.append(inc)
        return {
            "scenario": scenario,
            "first_decision": dec1.model_dump(),
            "replay_decision": dec2.model_dump(),
            "incident": inc.model_dump(),
        }

    elif scenario == "channel":
        msg = Message.create(
            message_id=f"msg-chan-{uuid.uuid4().hex[:6]}",
            payload="Sensitive quantum tele-signed document",
            sender_id="alice@qds.bank",
            receiver_id="bob@qds.bank",
            timestamp=now,
        )
        # Intercept-resend attack
        sig, _ = ChannelAttackSimulator.simulate_intercept_resend(
            simulator=state.simulator,
            message=msg,
            signer_key="alice-hsm-secret-key-12345",
            session_id=state.active_session.session_id,
            nonce=f"nonce-chan-{uuid.uuid4().hex[:8]}",
            qubit_count=64,
        )
        dec = state.engine.verify(msg, sig, "bob@qds.bank", policy, current_time=now)

        inc = Incident(
            incident_id=f"INC-{uuid.uuid4().hex[:6]}",
            timestamp=now,
            attack_type=AttackType.CHANNEL_MANIPULATION,
            severity=IncidentSeverity.CRITICAL,
            decision_id=dec.decision_id,
            evidence=dec.statistics,
        )
        state.incidents.append(inc)
        return {"scenario": scenario, "decision": dec.model_dump(), "incident": inc.model_dump()}

    elif scenario == "self-healing":
        # Propose update
        new_pol = policy.model_copy()
        new_pol.version = f"1.0.{len(state.self_healing._checkpoints) + 1}"
        new_pol.max_qber_threshold = 0.075
        new_pol.max_clock_skew_seconds = 8.0

        bundle = state.self_healing.propose_update(
            candidate_policy=new_pol,
            change_rationale="Proactive security hardening: calibrated QBER threshold to 0.075",
        )
        # Shadow test
        passed, metrics = state.self_healing.run_shadow_tests(bundle.bundle_id)
        # Sign
        state.self_healing.approve_and_sign(bundle.bundle_id, state.admin_identity, state.admin_priv_b64)
        # Apply
        ckpt_id = state.self_healing.apply_update(bundle.bundle_id, state.admin_pub_b64)
        updated_version = state.self_healing.active_policy.version

        # Rollback demonstration
        rolled_back_policy = state.self_healing.rollback(ckpt_id)

        return {
            "scenario": "self-healing",
            "bundle_id": bundle.bundle_id,
            "shadow_tests_passed": passed,
            "shadow_metrics": metrics,
            "signature_present": bundle.ed25519_signature is not None,
            "deployed_version": updated_version,
            "rollback_successful": rolled_back_policy.version == "1.0.0",
            "active_version": state.self_healing.active_policy.version,
        }

    else:
        raise HTTPException(status_code=400, detail=f"Unknown scenario: {scenario}")


@app.get("/", response_class=HTMLResponse)
def dashboard_ui():
    """Renders self-contained, zero-external-dependency dark-mode security operator dashboard."""
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Eagle-Eye | QDS Cyber-Threat Detection Console</title>
<style>
  :root {
    --bg-main: #0B0F19;
    --bg-card: #111827;
    --border-color: #1F2937;
    --text-primary: #F9FAFB;
    --text-muted: #9CA3AF;
    --accent-blue: #3B82F6;
    --accent-green: #10B981;
    --accent-red: #EF4444;
    --accent-amber: #F59E0B;
    --accent-purple: #8B5CF6;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }
  body { background-color: var(--bg-main); color: var(--text-primary); padding: 24px; }
  header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 16px; margin-bottom: 24px; }
  .logo-title h1 { font-size: 22px; font-weight: 700; color: #FFFFFF; letter-spacing: 0.5px; }
  .logo-title p { font-size: 13px; color: var(--text-muted); margin-top: 4px; }
  .badge { padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
  .badge-healthy { background: rgba(16, 185, 129, 0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }
  .grid-container { display: grid; grid-template-columns: repeat(12, 1fr); gap: 20px; }
  .card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 18px; }
  .col-4 { grid-column: span 4; }
  .col-8 { grid-column: span 8; }
  .col-12 { grid-column: span 12; }
  .card h2 { font-size: 15px; font-weight: 600; margin-bottom: 14px; color: #E5E7EB; border-bottom: 1px solid #1F2937; padding-bottom: 8px; }
  .btn-group { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 16px; }
  button {
    background: #1F2937; border: 1px solid #374151; color: #FFFFFF; padding: 9px 14px;
    border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; transition: all 0.2s;
  }
  button:hover { background: #374151; border-color: #4B5563; }
  button.primary { background: #2563EB; border-color: #3B82F6; }
  button.primary:hover { background: #1D4ED8; }
  button.danger { background: #DC2626; border-color: #EF4444; }
  button.danger:hover { background: #B91C1C; }
  button.warning { background: #D97706; border-color: #F59E0B; }
  button.warning:hover { background: #B45309; }
  pre {
    background: #030712; border: 1px solid #1F2937; border-radius: 6px; padding: 14px;
    color: #10B981; font-size: 12px; overflow-x: auto; max-height: 280px;
  }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #1F2937; }
  th { color: var(--text-muted); font-weight: 600; }
  .verdict-ACCEPT { color: var(--accent-green); font-weight: bold; }
  .verdict-REJECT { color: var(--accent-red); font-weight: bold; }
  .verdict-ESCALATE { color: var(--accent-amber); font-weight: bold; }
</style>
</head>
<body>
  <header>
    <div class="logo-title">
      <h1>EAGLE-EYE | Security Operator Dashboard</h1>
      <p>Quantum-Inspired Cyber-Threat Detection for Teleportation-Based QDS (SIH PS 26141)</p>
    </div>
    <div>
      <span class="badge badge-healthy" id="system-status">System: Online (Zero AI/ML)</span>
    </div>
  </header>

  <div class="grid-container">
    <!-- Attack Paths Simulator Console -->
    <div class="card col-12">
      <h2>Attack Simulation & Verification Console</h2>
      <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 14px;">
        Trigger live verification scenarios across the four mandatory attack pathways and self-healing lifecycle:
      </p>
      <div class="btn-group">
        <button class="primary" onclick="runSim('valid')">Path 1: Valid QDS Teleportation (ACCEPT)</button>
        <button class="danger" onclick="runSim('forgery')">Path 2: Forgery & Tampered Payload (REJECT)</button>
        <button class="warning" onclick="runSim('replay')">Path 3: Replay & Nonce Reuse (REJECT)</button>
        <button class="danger" onclick="runSim('channel')">Path 4: Channel Manipulation (REJECT & QUARANTINE)</button>
        <button style="background:#7C3AED; border-color:#8B5CF6;" onclick="runSim('self-healing')">Path 5: Signed Self-Healing & Rollback</button>
      </div>
      <div>
        <h3 style="font-size: 13px; color: #9CA3AF; margin-bottom: 6px;">Live Execution Telemetry & Reason Codes:</h3>
        <pre id="output-telemetry">// Click an attack path above to trigger live QDS verification...</pre>
      </div>
    </div>

    <!-- Active Policy & Bounds -->
    <div class="card col-4">
      <h2>Active Security Policy</h2>
      <div id="policy-info" style="font-size: 13px; line-height: 1.8;">Loading policy...</div>
    </div>

    <!-- Confirmed Incidents -->
    <div class="card col-8">
      <h2>Threat Incidents Ledger</h2>
      <div style="overflow-x: auto; max-height: 220px;">
        <table>
          <thead>
            <tr><th>Incident ID</th><th>Attack Type</th><th>Severity</th><th>Status</th><th>Linked Decision</th></tr>
          </thead>
          <tbody id="incidents-table">
            <tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No incidents recorded yet.</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Immutable Audit Hash-Chain -->
    <div class="card col-12">
      <h2>Immutable SHA-256 Audit Trail (Hash Chain)</h2>
      <div style="overflow-x: auto; max-height: 320px;">
        <table>
          <thead>
            <tr><th>Decision ID</th><th>Verdict</th><th>Timestamp</th><th>Reasons / Checks</th><th>Event Hash (SHA-256)</th><th>Previous Hash</th></tr>
          </thead>
          <tbody id="audit-table">
            <tr><td colspan="6" style="text-align:center; color: var(--text-muted);">No audit events recorded yet.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

<script>
async function loadState() {
  try {
    const polRes = await fetch('/api/policy');
    const pol = await polRes.json();
    document.getElementById('policy-info').innerHTML = `
      <div><strong>Version:</strong> <span style="color:#10B981">${pol.version}</span></div>
      <div><strong>Max QBER (Reject):</strong> ${pol.max_qber_threshold}</div>
      <div><strong>Escalate QBER:</strong> ${pol.escalate_qber_threshold}</div>
      <div><strong>Max TVD:</strong> ${pol.max_tvd_threshold}</div>
      <div><strong>Confidence Level:</strong> ${(pol.confidence_level * 100).toFixed(0)}%</div>
      <div><strong>Max Clock Skew:</strong> ${pol.max_clock_skew_seconds}s</div>
      <div><strong>Min Sample Size:</strong> ${pol.min_qubit_sample_size} qubits</div>
    `;

    const incRes = await fetch('/api/incidents');
    const incs = await incRes.json();
    const incBody = document.getElementById('incidents-table');
    if (incs.length > 0) {
      incBody.innerHTML = incs.map(i => `
        <tr>
          <td><code>${i.incident_id}</code></td>
          <td><span style="color:#EF4444; font-weight:600;">${i.attack_type}</span></td>
          <td>${i.severity}</td>
          <td>${i.status}</td>
          <td><code>${i.decision_id}</code></td>
        </tr>
      `).join('');
    }

    const audRes = await fetch('/api/audit');
    const aud = await audRes.json();
    const audBody = document.getElementById('audit-table');
    if (aud.records && aud.records.length > 0) {
      audBody.innerHTML = aud.records.slice().reverse().map(r => `
        <tr>
          <td><code>${r.decision_id}</code></td>
          <td class="verdict-${r.verdict}">${r.verdict}</td>
          <td>${new Date(r.timestamp * 1000).toLocaleTimeString()}</td>
          <td>${r.reasons.join(', ')}</td>
          <td><code title="${r.event_hash}">${r.event_hash ? r.event_hash.substring(0, 16) + '...' : ''}</code></td>
          <td><code title="${r.previous_event_hash}">${r.previous_event_hash ? r.previous_event_hash.substring(0, 16) + '...' : ''}</code></td>
        </tr>
      `).join('');
    }
  } catch(e) {
    console.error(e);
  }
}

async function runSim(scenario) {
  const out = document.getElementById('output-telemetry');
  out.textContent = `Executing scenario: ${scenario}...`;
  try {
    const res = await fetch(`/api/simulate/${scenario}`, { method: 'POST' });
    const data = await res.json();
    out.textContent = JSON.stringify(data, null, 2);
    loadState();
  } catch(e) {
    out.textContent = `Error: ${e.message}`;
  }
}

window.onload = loadState;
</script>
</body>
</html>
"""
    return HTMLResponse(content=html_content)
