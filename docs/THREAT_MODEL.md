# Eagle-Eye — Threat Model & Security Controls (SIH PS 26141)

## 1. Threat Profile & Asset Classification

### Protected Assets
1. **Quantum Signature State Vectors & Bases**: Teleported states $|\psi_i\rangle$ and Alice's secret basis choices.
2. **Canonical Message Bindings**: Cryptographic association between message $M$, nonce $N$, and quantum state sequence.
3. **Verification Policy & Baselines**: Detection thresholds ($QBER_{threshold}$, $TVD_{threshold}$, confidence intervals).
4. **Audit Trail & Decision Ledger**: Cryptographic hash chain of verification verdicts and incident evidence.
5. **Self-Healing Rule Bundles**: Cryptographically signed updates and rollback checkpoints.

---

## 2. Threat Vector Analysis & Controls Matrix

| Threat Vector | STRIDE Classification | Attack Mechanism | Eagle-Eye Security Control | Detection & Response | Mandatory Test Case |
|---|---|---|---|---|---|
| **Quantum Forgery** | Tampering / Repudiation | Eavesdropper Eve alters quantum states or introduces fabricated signature states. | Quantum state tomography and projective measurements across $X, Y, Z$ bases. | Anomalous QBER exceeding confidence bounds; high Total Variation Distance ($TVD > \delta$). Verdict: `REJECT` or `ESCALATE`. | `tests/attacks/test_forgery.py` |
| **Classical Tampering** | Tampering | Modification of message $M'$ while keeping original signature state vector $\sigma$. | Canonical payload binding using SHA-256 HMAC and state alignment checks. | Signature verification fails canonical digest consistency check. Verdict: `REJECT`. | `tests/attacks/test_forgery.py::test_modified_message_rejection` |
| **Signer Impersonation** | Spoofing | Eve presents a signature claiming to be Alice with unknown/mismatched identity key or invalid context. | Cryptographic identity registry, public key signature validation, role-context binding. | Unknown identity or invalid signature key rejected immediately. Verdict: `REJECT`. | `tests/attacks/test_impersonation.py` |
| **Replay Attack** | Spoofing / Tampering | Eve retransmits previously accepted valid signature packet to verify duplicate transaction. | Freshness guards: sliding nonce cache, monotonically increasing counter, strict timestamp window ($\pm \Delta t$). | Duplicate nonce or expired timestamp rejected with 100% detection. Verdict: `REJECT`. | `tests/attacks/test_replay.py` |
| **Channel Disruption** | Denial of Service | Active quantum channel disturbance (depolarizing, bit-flip, phase-flip, burst errors). | Statistical divergence testing (Wilson score confidence interval, Sequential Probability Ratio Test). | Distinguishes honest noise from targeted channel manipulation; quarantines degraded links. Verdict: `ESCALATE` or `REJECT`. | `tests/attacks/test_channel.py` |
| **Unauthorized Verification** | Information Disclosure | Unauthorized verifier probes API to deduce signature bits or side-channel leakage. | Role-Based Access Control (RBAC), verification purpose tokens, rate limiting. | Rejects query, logs security alarm, prevents oracle exploitation. Verdict: `REJECT`. | `tests/attacks/test_unauthorized.py` |
| **Policy & Audit Tampering** | Elevation of Privilege | Attacker attempts to modify detection thresholds in policy files or rewrite audit trail. | Ed25519 digitally signed policy bundles and SHA-256 hash-chained immutable event ledger. | Signature verification fails; verifier detects chain break and enters fail-closed state. | `tests/security/test_policy_tampering.py` |
| **Malicious / Bad Self-Healing Update** | Elevation of Privilege | Rogue update introduces permissive thresholds or regressions. | Shadow testing against golden regression corpus before activation; signed approvals; automatic rollback. | Shadow test failure or rollback instruction restores previous known-good baseline. | `tests/resilience/test_self_healing.py` |

---

## 3. Fail-Closed Security Posture
In accordance with Anti-Gravity execution guidelines:
- If identity is invalid $\rightarrow$ Fail closed (`REJECT`).
- If freshness check fails $\rightarrow$ Fail closed (`REJECT`).
- If policy signature is invalid or tampered $\rightarrow$ Fail closed (`REJECT`).
- If evidence payload is incomplete or corrupted $\rightarrow$ Fail closed (`REJECT`).
- No silent accepts under any circumstances.
