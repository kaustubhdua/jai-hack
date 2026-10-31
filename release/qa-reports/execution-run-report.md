# Five-Minute Judging Demonstration Script & Run Report

> **Historical archive — not current verification.** This file preserves an earlier run and may describe obsolete models, metrics, interfaces, or CSV schemas. Do not use it as current evidence for judging, submission, or presentation claims. Regenerate results from current `main` and authorized organizer data. The current workflow is [docs/evaluation](../../docs/evaluation.md); the current Level 2 contract is [docs/level2-brief](../../docs/level2-brief.md).


**Audience:** Hackathon Judges, Technical Evaluators, Cybersecurity Practitioners  
**Total Run Time:** 5 Minutes  
**Data Basis:** Real Local CICIDS2017 Holdout Flows (`data/processed/eval_prepared.parquet`)  

---

## 1. Demonstration Philosophy

This demonstration is designed to be **predictable, live-demonstrable, and grounded entirely in real local execution**. It does not rely on mocked API calls, synthetic sleep loops, or fabricated telemetry. Every number shown in the UI is directly produced by the backend five-agent engine.

---

## 2. Minute-by-Minute Demonstration Script

### Minute 1: The Threat & Five-Agent Architecture
* **Screen:** Open `/architecture` console.
* **Talking Points:**
  - "Traditional firewalls rely on static rules or single-point ML classifiers that suffer from high false-alarm rates and overfitting."
  - "CyberSentinel deploys a collaborative **five-agent defensive mesh**:"
    1. *Agent 1 (Threat Classifier):* Identifies known multi-class attack signatures (DoS, DDoS, Port Scan, Brute Force).
    2. *Agent 2 (Anomaly Detector):* Unsupervised Isolation Forest calibrated on benign baseline to catch zero-day deviations.
    3. *Agent 3 (Evidence Fusion):* Evaluates consensus. Only corroborated attacks trigger autonomous block recommendations; disagreements safely route to human review.
    4. *Agent 4 (Temporal Correlation):* Tracks sliding-window connection frequency across ports and endpoints.
    5. *Agent 5 (Adaptive Defense):* Synthesizes time-bounded quarantine policies without kernel interference.

### Minute 2: Evidence Fusion & Explainable Disagreement
* **Screen:** Open `/fusion` console.
* **Live Action:**
  - Point to the 3x3 consensus matrix.
  - "Look at the diagonal: when Agent 1 and Agent 2 both identify an attack, the decision is autonomous **BLOCK**. When both identify benign traffic, the decision is **ALLOW**."
  - "Now examine the off-diagonal cells: when Agent 1 suspects an attack but Agent 2 views it as normal baseline distribution, or vice versa, the system flags **DISAGREE** and routes the flow to **REVIEW**."
  - Click on a `DISAGREE` flow row to open the Flow Inspector drawer, displaying the exact feature values (`Flow Duration`, `Packet Length Mean`) that caused the divergence.

### Minute 3: Causal Replay & Policy Synthesis
* **Screen:** Open `/replay` console.
* **Live Action:**
  - Click **Start Replay** on the 114,185 evaluation dataset.
  - Observe the live FPS counter reaching **7,000+ flows per second** and completing the entire dataset in under 17 seconds.
  - Highlight the causality counter:
    - 20,368 time-bounded policies spawned.
    - 48,264 attack flows actively blocked before reaching target assets (89.1% containment).
    - **Zero self-blocking violations:** Every policy is activated strictly *after* the triggering packet passes.

### Minute 4: Submission Studio & Strict Semantic Validation
* **Screen:** Open `/submissions` console.
* **Live Action:**
  - View the generated file badges: `classification.csv` (114,185 rows), `policy.csv` (20,368 rules), and `replay.csv` (114,185 actions).
  - Point to the live validation card:
    - Status: `READY_FOR_SUBMISSION` (Green indicator).
    - Classification Errors: `0`.
    - Policy Errors: `0`.
    - Replay Errors: `0`.
  - Click **Download Bundle** to demonstrate instantaneous client-side export.

### Minute 5: Adversarial Hardening & Safety Boundaries
* **Screen:** Open terminal or `/settings` console.
* **Live Action:**
  - Run `pytest tests/test_adversarial_agents.py` showing all 19 adversarial tests passing in 6 seconds.
  - Emphasize the core safety guarantee:
    - "CyberSentinel is an **offline replay and decision-support system**. All ALLOW, BLOCK, and REVIEW actions are simulated recommendations within memory state tables. The system strictly adheres to safety boundaries: it never accesses host root privileges, modifies kernel iptables/eBPF tables, or intercepts live host networking."
  - Conclude: "CyberSentinel delivers high-throughput, explainable, and causally valid adaptive cybersecurity ready for real-world SOC workflows."

