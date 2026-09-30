# Eagle-Eye: Benchmark Evaluation Report
> **SIH PS 26141** | Evaluation Date: 2026-09-30 | Seeds: 30

## 1. Executive Summary & Target Gate Status

| Metric Target | Engineering Goal | Measured Result | Gate Status |
|---|---|---|---|
| **Replay Rejection** | 100% | 100.0% | [PASSED] |
| **Honest Acceptance** | >= 95% | 100.0% | [PASSED] |
| **Attack Detection** | >= 90% | 100.0% | [PASSED] |
| **False Acceptance Rate (FAR)** | <= 5% | 0.0% | [PASSED] |
| **Decision Latency (Mean)** | <= 1000 ms | 0.15 ms | [PASSED] |
| **Evidence Completeness** | 100% | 100.0% | [PASSED] |
| **Rollback Success** | 100% | 100.0% | [PASSED] |

## 2. Per-Class Attack Detection Rates

| Attack Corpus | Category | Total Tested | Detection Rate |
|---|---|---|---|
| **Corpus F** | Classical & Quantum Forgery | 120 | **100.0%** |
| **Corpus I** | Signer & Context Impersonation | 90 | **100.0%** |
| **Corpus R** | Replay & Freshness Violations | 120 | **100.0%** |
| **Corpus C** | Channel Intercept-Resend & Jamming | 90 | **100.0%** |
| **Corpus E** | Stale Skew & Sample Edge Cases | 60 | **100.0%** |

## 3. Comparative Architecture Analysis

| Framework / Approach | Attack Detection Rate | False Acceptance (FAR) | Failure Modes & Vulnerabilities |
|---|---|---|---|
| **Baseline 1 (Fixed QBER Only)** | 6.2% | 93.8% | Fails to detect replays, identity spoofing, and message payload tampering |
| **Baseline 2 (QBER + TVD)** | 6.2% | 93.8% | Detects quantum distortion but blind to classical tampering and replay attacks |
| **Eagle-Eye (Full Framework)** | **100.0%** | **0.0%** | Holistic defense combining guards, freshness, multi-statistic SPRT/QBER/TVD, and signed lifecycle |

## 4. Performance & Throughput
- **Mean Latency**: `0.15 ms`
- **95th Percentile Latency**: `0.48 ms`
- **Throughput**: `310.2 verifications/sec`
- **Total Benchmark Decisions Evaluated**: `630`