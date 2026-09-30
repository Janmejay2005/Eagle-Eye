# Eagle-Eye — Known Limitations & Protocol Assumptions (SIH PS 26141)

## 1. Physical Quantum Security Boundary
- **Software Simulation Scope**: Eagle-Eye executes on a classical CPU environment. The simulation uses deterministic mathematical state vectors and Born-rule projective measurement sampling. While the verification logic and statistical thresholds reflect true quantum mechanics, classical memory itself cannot provide physical information-theoretic non-cloning security.
- **Hardware Integration Roadmap**: In a future V2 physical deployment, the software simulator module will be swapped for an optical QKD/QDS hardware adapter interfacing with Single Photon Avalanche Diodes (SPADs) and laser sources.

## 2. Finite-Sample Statistical Bounds
- For small block sizes ($N < 16$ qubits), statistical variance is elevated. The Wilson score confidence interval and Wald SPRT boundaries widen, requiring wider margins to prevent false rejections.
- To ensure mathematical rigor, Eagle-Eye sets a hard fail-closed gate when $N < \text{min\_qubit\_sample\_size}$.

## 3. Clock Skew & Classical Synchronization
- Freshness protection relies on coordinated time between signer and verifier within `max_clock_skew_seconds` (default $\pm 10$ seconds). Environments subject to high network latency or unsynchronized RTCs must use monotonic sequence numbering or sliding window token caches.

## 4. Zero AI/ML Principle
- By design, Eagle-Eye excludes black-box machine learning or neural networks. While this ensures 100% explainability, deterministic auditability, and immunity to adversarial AI evasion, it means anomalous channel disturbances outside modeled noise types (e.g. exotic multi-photon side-channel emissions) must be identified through projective statistics (TVD, basis asymmetry) rather than heuristic clustering.
