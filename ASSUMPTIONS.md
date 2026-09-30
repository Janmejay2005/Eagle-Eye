# Eagle-Eye — Protocol Assumptions & Security Model (SIH PS 26141)

## 1. Simulation Scope & Boundary
- **Software Simulation**: Eagle-Eye is a deterministic simulation and statistical verification framework. It simulates quantum state vectors, entanglement distribution, teleportation, and projective measurement statistics.
- **Physical Security Boundary**: Classical software cannot generate physical quantum non-cloning guarantees. Security bounds apply to the mathematical model of the teleportation-based Quantum Digital Signature (QDS) protocol. Simulated verification results must never be misrepresented as hardware-secured quantum photons.

## 2. Quantum Protocol Assumptions
- **Entangled Bell Pairs**: Maximally entangled Bell pairs $|\Phi^+\rangle = \frac{1}{\sqrt{2}}(|00\rangle + |11\rangle)$ are generated and distributed between parties or mediated via a relay.
- **State Teleportation**: Signer (Alice) teleports signature qubit states $|\psi\rangle$ (derived from cryptographic message hashing and secret key basis choices) to the recipient (Bob) or verifiers.
- **Pauli Corrections**: Classical transmission conveys Bell-basis measurement outcomes $(m_1, m_2 \in \{0, 1\})$. The receiver applies $X^{m_2} Z^{m_1}$ Pauli corrections to restore the quantum state.
- **Measurement Abstraction**: Projective measurements are evaluated across Pauli bases:
  - $Z$-basis: $\{|0\rangle, |1\rangle\}$
  - $X$-basis: $\{|+\rangle, |-\rangle\} = \{\frac{1}{\sqrt{2}}(|0\rangle + |1\rangle), \frac{1}{\sqrt{2}}(|0\rangle - |1\rangle)\}$
  - $Y$-basis: $\{|R\rangle, |L\rangle\} = \{\frac{1}{\sqrt{2}}(|0\rangle + i|1\rangle), \frac{1}{\sqrt{2}}(|0\rangle - i|1\rangle)\}$
- **Honest Noise Baseline**: Normal quantum channel imperfections are modeled with depolarizing, bit-flip, and phase-flip rates parameterized up to $QBER_{baseline} \le 0.05$.

## 3. Threat Model Assumptions
- **Adversary Capabilities**:
  - Intercept-resend or quantum channel manipulation causing anomalous QBER, basis-dependent error skew, or distribution divergence.
  - Classical message tampering and signature forgery attempts.
  - Replay of previously accepted valid signature packets with duplicated nonces or stale timestamps.
  - Signer impersonation using unregistered or mismatched identity keys.
  - Unauthorized verification probes attempting eavesdropping or verification parameter extraction.
- **Classical Channel Security**: Metadata and classical messages are authenticated using standard message authentication codes and canonical serialization to guarantee integrity.

## 4. Verification & Self-Healing Guarantees
- **Deterministic Decisions**: Verifier evaluates inputs deterministically: `ACCEPT`, `REJECT`, or `ESCALATE`.
- **Explainability**: Every non-acceptance outcome strictly provides human-readable and machine-parseable reason codes and observed statistical bounds.
- **Zero AI/ML**: No black-box neural networks or probabilistic heuristics. Only verifiable quantum statistics (QBER, Wilson score intervals, Total Variation Distance, Sequential Probability Ratio Tests).
- **Controlled Self-Healing**: Incident updates are gated by regression test suites, cryptographic approval signatures, and instant rollback capabilities.
