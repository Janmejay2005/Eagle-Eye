# Eagle-Eye — Benchmark Specification

Evaluation plan and reproducible metrics (SIH PS 26141)

## 1. Purpose
This document defines what Eagle-Eye will measure. Values must be measured from the implementation; targets below are engineering goals, not assumed results.

## 2. Test Corpus
| Corpus | Name | Contents |
|---|---|---|
| **H** | Honest | Honest signatures under ideal and controlled-noise conditions. |
| **F** | Forgery | Random and structured forgery attempts; altered message/signature pairs. |
| **I** | Impersonation | Identity/context mismatches and unauthorized attempts. |
| **R** | Replay | Captured valid events replayed with stale, duplicate, or altered freshness metadata. |
| **C** | Channel Disturbance | Channel disturbances: flips, basis bias, burst errors, delay, loss, mixed noise. |
| **E** | Edge Cases | Small samples, missing fields, clock skew, zero counts, restart, rollback. |

## 3. Primary Metrics
- **FAR (False Acceptance Rate)**: malicious attempts accepted / malicious attempts tested.
- **FRR (False Rejection Rate)**: honest attempts rejected / honest attempts tested.
- **Detection rate per attack class**: proportion of attack scenarios correctly flagged.
- **Alert precision**: true positive alerts / total alerts generated.
- **Decision latency**: elapsed execution time per verification decision.
- **Throughput**: verifications evaluated per second.
- **Confidence coverage**: percentage of statistical decisions within target confidence interval.
- **Replay rejection rate**: percentage of duplicate nonces rejected (target 100%).
- **Evidence completeness**: percentage of decisions preserving full inputs, metrics, and event hashes (target 100%).
- **Self-healing recovery time**: duration to revert a faulty rule or baseline update.

## 4. Measurement Protocol
- Fix software, dependency, protocol, policy, and simulator versions.
- Record seed, shots, state, basis, noise model, channel parameters, and attack parameters.
- Run at least 30 independent seeds for prototype evaluation; report mean, standard deviation, and confidence interval.
- Keep honest and attack corpora separate from tuning.
- Report per attack type and combined; never only aggregate accuracy.
- Repeat after every policy/self-healing update.

## 5. Suggested Target Gates
| Metric | Prototype Target | Interpretation |
|---|---|---|
| **Replay rejection** | 100% controlled corpus | Mandatory freshness works. |
| **Honest acceptance** | $\ge 95\%$ declared noise model | Avoid over-rejecting honest signers. |
| **Attack detection** | $\ge 90\%$ per class | Initial research target; publish measured actuals. |
| **FAR** | $\le 5\%$ controlled corpus | Minimize acceptance of adversary actions. |
| **Latency** | $\le 1$ second simulator profile | High responsiveness for verification pipeline. |
| **Evidence completeness** | 100% | Full audit ledger compliance. |
| **Rollback success** | 100% test scenarios | Reversibility and resilience of self-healing. |

## 6. Baseline Comparisons
1. **Baseline 1**: Fixed QBER threshold only.
2. **Baseline 2**: QBER plus distribution distance.
3. **Eagle-Eye**: Protocol checks + freshness + multi-statistic decision + signed policy lifecycle.
