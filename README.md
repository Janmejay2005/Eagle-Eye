# Eagle-Eye: Quantum-Inspired Cyber-Threat Detection for Teleportation-Based Quantum Digital Signatures (QDS)

[![PyPI version](https://img.shields.io/pypi/v/eagle-eye-qds.svg)](https://pypi.org/project/eagle-eye-qds/)
[![Python versions](https://img.shields.io/pypi/pyversions/eagle-eye-qds.svg)](https://pypi.org/project/eagle-eye-qds/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

> **SIH PS 26141** | Smart India Hackathon  
> Deterministic, explainable security framework for teleportation-based QDS with zero AI/ML reliance.

---

## Overview

**Eagle-Eye** is a comprehensive verification and threat detection platform built for teleportation-based Quantum Digital Signatures. By combining:
- Bell-state entanglement distribution ($|\Phi^+\rangle$),
- Quantum teleportation with classical Pauli corrections ($I, X, Z, XZ$),
- Projective Pauli measurements across $X$, $Y$, and $Z$ bases,
- Cryptographic freshness guards (anti-replay, timestamp skew control, canonical binding),
- Rigorous quantum statistical hypothesis testing (Wilson score intervals, Total Variation Distance, Sequential Probability Ratio Tests),
- Tamper-evident SHA-256 hash-chained audit ledgers,
- Cryptographically signed and reversible self-healing policy updates, and
- An interactive security operator dashboard with live attack scenario demonstrations,

Eagle-Eye provides mathematical guarantees, deterministic verdicts (`ACCEPT`, `REJECT`, `ESCALATE`), and explainable reason codes for quantum and classical threat vectors.

---

## Key Architectural Principles

1. **Zero AI/ML**: No black-box neural networks or unexplainable heuristics. Every security decision is grounded in verifiable quantum information statistics.
2. **Deterministic & Explainable**: Identical inputs and seeds yield identical decisions. Every rejected or escalated verification explains the exact failed check and measured statistic.
3. **Fail-Closed Design**: Any identity ambiguity, freshness breach, policy corruption, or statistical anomaly immediately fails closed (`REJECT`).
4. **Controlled Self-Healing**: Incident updates cannot auto-deploy. They must pass shadow regression testing, require digital cryptographic authorization, and remain 100% reversible via signed rollback checkpoints.
5. **Clear Simulation Scope**: Distinguishes software quantum state simulation from physical photon-level hardware; models realistic channel noise without over-claiming hardware guarantees.

---

## Directory Structure

```
eagle-eye/
├── pyproject.toml             # Python build specification
├── requirements.txt           # Locked dependency definitions
├── LICENSE                    # Apache-2.0 License
├── README.md                  # System documentation & quickstart
├── CONTRIBUTING.md            # Branch policy & contribution standards
├── ASSUMPTIONS.md             # Cryptographic & quantum channel assumptions
├── docs/                      # Governance & verification documentation
│   ├── PRD_MAPPING.md         # Matrix mapping FR-01..10 to test suites
│   ├── THREAT_MODEL.md        # STRIDE threat model & controls
│   └── BENCHMARK.md           # Benchmark protocol & target gates
├── src/                       # Core Eagle-Eye framework
│   ├── schemas/               # Phase 1: Pydantic schemas
│   ├── protocol/              # Phase 2: Quantum state & teleportation engine
│   ├── guards/                # Phase 3: Freshness, identity & canonical binding
│   ├── statistics/            # Phase 4: QBER, distances, confidence bounds (no AI)
│   ├── attacks/               # Phase 5: Attack scenario generators
│   ├── decision/              # Phase 6: Verdict engine & audit log chain
│   ├── self_healing/          # Phase 7: Signed rule lifecycle & rollback
│   ├── dashboard/             # Phase 8: Live operator dashboard & web UI
│   └── benchmark/             # Phase 9: Evaluation engine & report generator
└── tests/                     # Multi-layer test suite
    ├── unit/                  # Unit tests (Bell state, Pauli, QBER, etc.)
    ├── contract/              # API and schema validation tests
    ├── integration/           # End-to-end verification pipeline tests
    ├── attacks/               # Attack simulation suite (4 core attacks)
    ├── security/              # Audit tampering & policy integrity tests
    └── resilience/            # Self-healing, bad updates, and rollback tests
```

---

## Quickstart

### 1. Installation

#### Option A: Install from PyPI
```bash
pip install eagle-eye-qds
```

#### Option B: Local Development Setup
```powershell
git clone https://github.com/vibeee45/Eagle-Eye.git
cd Eagle-Eye
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Running Test Suite
```powershell
.\.venv\Scripts\pytest -v
```

### 3. Running Benchmarks
```powershell
.\.venv\Scripts\python -m src.benchmark.benchmark_runner
```

### 4. Launching the Security Dashboard
```powershell
.\.venv\Scripts\uvicorn src.dashboard.app:app --host 127.0.0.1 --port 8000 --reload

```
