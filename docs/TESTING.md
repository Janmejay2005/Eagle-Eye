# Eagle-Eye — Testing Specification

Verification, security, regression, and resilience testing (SIH PS 26141)

## 1. Testing Principles
- Test protocol, detector, policy, response, and self-healing separately and together.
- Use deterministic seeds and golden vectors.
- Test honest noise and adversarial manipulation.
- A detector must preserve honest acceptance and explain every decision.

## 2. Test Layers
| Layer | Examples |
|---|---|
| **Unit** | Bell-state/teleportation; Pauli corrections; bases; QBER; distances; bounds; nonce validation. |
| **Contract/API** | Schema validation, required fields, versions, errors, idempotency. |
| **Integration** | Request through verification, decision, evidence, dashboard, response. |
| **Attack simulation** | Forgery, impersonation, replay, channel manipulation, unauthorized verification. |
| **Security** | Tampered message, policy, audit, dependency, identity, timestamp, configuration. |
| **Performance** | Latency, throughput, memory, concurrency, large sample blocks. |
| **Resilience** | Restart, corrupted cache, unavailable component, rollback, duplicate incident. |
| **User acceptance** | Operator understands reason, evidence, severity, recommendation. |

## 3. Mandatory Test Cases
1. Valid signature under ideal conditions $\rightarrow$ `ACCEPT`.
2. Honest signature under declared noise $\rightarrow$ `ACCEPT` or controlled `ESCALATE`.
3. Modified message with original signature $\rightarrow$ `REJECT`.
4. Forged signature $\rightarrow$ `REJECT` or `ESCALATE` with reason.
5. Unknown signer/context $\rightarrow$ `REJECT`.
6. Valid signature replayed with same nonce/session $\rightarrow$ `REJECT`.
7. Stale timestamp or clock skew $\rightarrow$ `REJECT` or `ESCALATE`.
8. Channel disturbance $\rightarrow$ statistical evidence and correct decision.
9. Unauthorized verifier $\rightarrow$ deny disclosure and log.
10. Tampered policy/audit $\rightarrow$ integrity failure and fail closed.
11. Confirmed incident $\rightarrow$ update only after regression tests.
12. Bad update $\rightarrow$ rollback and retain evidence.

## 4. Test Oracle
Every test defines input, expected reason, expected decision, versions, seed, sample size, and tolerance. Quantum outputs are probabilistic; assert statistical ranges unless using a deterministic mock.

## 5. Exit Criteria
- Mandatory tests pass.
- No critical/high unresolved security defect.
- Replay rejection is 100% controlled corpus.
- FAR/FRR and per-class detection reported with intervals.
- Evidence completeness is 100%.
- Self-healing update and rollback demonstrated.
- Known limitations documented.
