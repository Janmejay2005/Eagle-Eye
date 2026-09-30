# Eagle-Eye — Contributing & Branching Policy

## Branch Policy
- `main`: Production-ready, verified code. Protected branch.
- `develop`: Integration branch for completed phase milestones.
- `feature/<phase-id>-<name>`: Feature branches for specific phases (e.g., `feature/phase1-schemas`).
- `fix/<defect-id>`: Hotfix branches for addressing test/security regression defects.

## Code Standards
- Strict typing and docstrings for all modules.
- Absolute separation of concerns:
  - `protocol`: Quantum simulator, Bell-state distribution, teleportation, Pauli corrections.
  - `guards`: Canonical binding, identity, freshness, session controls.
  - `statistics`: Deterministic quantum metrics (QBER, distribution distance, confidence bounds, sequential tests). No AI/ML models.
  - `policy`: Verifier policy engine, rulesets, thresholds, fail-closed handling.
  - `attacks`: Deterministic attack simulations (forgery, impersonation, replay, channel disruption, unauthorized verification).
  - `decision`: Verdict engine (ACCEPT / REJECT / ESCALATE) and immutable audit log chain.
  - `self_healing`: Signed incident-driven proposal, shadow testing, baseline versioning, manual approval, cryptographic rollback.
  - `dashboard`: Real-time audit, verification review, and attack demonstration interface.
- 100% reproducible execution using explicit random seeds.
- Comprehensive unit and integration test coverage for every phase.
