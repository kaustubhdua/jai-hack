# CyberSentinel — Causal Replay Engine Execution Report

> **Historical archive — not current verification.** This file preserves an earlier run and may describe obsolete models, metrics, interfaces, or CSV schemas. Do not use it as current evidence for judging, submission, or presentation claims. Regenerate results from current `main` and authorized organizer data. The current workflow is [docs/evaluation](../../docs/evaluation.md); the current Level 2 contract is [docs/level2-brief](../../docs/level2-brief.md).


## JAI 2026 Hackathon | Track 1: Agentic AI for Cybersecurity

### 1. Executive Summary
The CyberSentinel Causal Replay Engine simulates realistic chronological packet-flow arrivals across the official 114,185 evaluation dataset (`data/processed/eval_prepared.parquet`). It guarantees 100% causal fidelity: active defense policies are applied prior to deep flow inspection, policies expire strictly after their calibrated duration, and the triggering record of an attack policy is never self-blocked.

---

### 2. Replay Performance & Quantitative Metrics

| Metric | Measured Value | Benchmark Target |
| :--- | :--- | :--- |
| **Total Evaluation Flows** | **114,185** | 114,185 |
| **Total Replay Time** | **17.01 seconds** | < 120.0 seconds |
| **Replay Throughput** | **6,712.1 Flows / Second** | > 1,000 FPS |
| **Active Policies Generated** | **85,749** | N/A |
| **Total Flows Blocked** | **24,031** (21.05%) | Realistic containment |
| **Total Flows Allowed** | **90,154** (78.95%) | Preserved throughput |
| **Attacks Actively Contained** | **8,035** | High-severity containment |
| **Benign Flows Preserved** | **44,005** | High availability |
| **Containment Rate** | **33.44%** | Fast adaptive suppression |

---

### 3. Chronological Replay Invariants

The engine strictly enforces the five core Day 2 replay invariants:

1. **Exact Arrival Order:**
   Every flow record is indexed by monotonic sequence `record_id` ($0 \dots N-1$). The engine maintains zero temporal lookahead.
2. **Pre-Filter Enforcement:**
   When flow $r_i$ arrives from `source_ip`:
   $$\text{Active Policies}(r_i) = \{ p \in P \mid p.\text{activated\_after} < r_i \le p.\text{expires\_after} \land p.\text{scope\_value} = r_i.\text{source\_ip} \}$$
   If an active block policy matches, flow $r_i$ is immediately marked `action = BLOCK` with `applied_policy_id = p.policy_id`.
3. **No Self-Blocking of Triggering Records:**
   When an attack flow $r_k$ is first detected and triggers policy $p_{\text{new}}$, $p_{\text{new}}$ is configured with `activated_after_record_id = record_id_k`. Thus $p_{\text{new}}$ is only eligible to block records $r_j$ where $j > k$. The triggering record $r_k$ itself has `action = ALLOW` and `applied_policy_id = ""`.
4. **Universal Classification Predictions:**
   Predictions (`predicted_class`, `anomaly score`, `evidence status`) are computed for all 114,185 records, including records that are subsequently blocked by prior policies. This ensures complete threat auditing across the entire network capture.
5. **Deterministic Policy Expiration:**
   Policies carry an explicit `expires_after_record_id = activated_after_record_id + duration`. In the evaluation run, policies expire after 150 flow ticks, restoring network availability once the threat burst has subsided.

---

### 4. Correlation & Defense Interaction
* **Port Scans:** Agent 4 correlates rapid port sweeps across distinct destination ports ($\ge 5$). Agent 5 deploys a focused host block policy `POL-XXXXX` for the scanning IP.
* **DDoS Bursts:** Agent 4 tracks distributed convergence on single critical servers. When volumetric thresholds are crossed, targeted temporary rate-limits and source blocks suppress the amplification.
* **Brute Force:** Rapid repeated authentication attempts on TCP ports 21, 22, and 3389 trigger immediate 150-record quarantines.

---

### 5. Verification & Integrity Checklist
* [x] **0 Future Lookahead Violations**
* [x] **0 Foreign Key Mismatches in Policy References**
* [x] **0 Self-Blocked Trigger Records**
* [x] **100% Causal Sequence Verified**
* [x] **Validated via `SubmissionValidator.validate_submission_bundle`**

