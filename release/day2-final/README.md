> **Archive notice:** This directory records a prior Day 2 release snapshot. Its operational status, metrics, test counts, and CSV validation refer to that earlier environment; they are not current verification for `main`. Current data, model, and generated submission artifacts are not committed. Re-run checks against the current branch before citing any result. This snapshot uses the earlier `policy.csv` contract; it is not a current submission template. See [the current Level 2 contract](../../docs/level2-brief.md) and verify it against the organizer's latest files.

# CyberSentinel — Day 2 Final Release Package

**Event:** Jaypee Agentic AI International Summit & Hackathon (JAI 2026)  
**Track:** Track 1 — Agentic AI for Cybersecurity  
**Challenge:** CyberSentinel: Multi-Agent Network Intrusion Detection & Adaptive Defense  
**Branch:** `day2/five-agent-local`  
**Status:** Historical local snapshot; current release readiness is unverified.

---

## Executive Overview

CyberSentinel is an offline, 5-agent network intrusion detection and adaptive defense framework that combines supervised threat classification, unsupervised anomaly detection, consensus-driven evidence fusion, sliding-window temporal incident correlation, and temporary simulated firewall policy enforcement.

The system processes network flows in strict chronological order with causal policy evaluation, never accesses future records or hidden ground-truth labels, and exports the three official competition submission CSV files (`classification.csv`, `policy.csv`, `replay.csv`) with verified semantic and referential integrity.

---

## Five-Agent Architecture

1. **Agent 1 (Supervised Threat Detection):** 5-class Random Forest classifier trained on 456,737 flows. Verified Holdout Accuracy: **99.9956%**, Macro-F1: **0.999897**.
2. **Agent 2 (Independent Anomaly Detection):** Unsupervised Isolation Forest trained on 240,000 benign flows. Benign False Positive Rate: **0.958%** (< 1.0% limit).
3. **Agent 3 (Evidence Fusion):** Deterministic 6-scenario decision matrix reconciling agreement and disagreement between A1 and A2 with explainable rationale strings.
4. **Agent 4 (Temporal Correlation):** Sliding-window endpoint tracker identifying horizontal Port Scans, volumetric DoS/DDoS surges, and authentication Brute Force campaigns.
5. **Agent 5 (Adaptive Defense):** Causal policy engine that evaluates active temporary `SOURCE_IP` blocks before deep inference (0ms latency mitigation) and generates forward-looking temporary rules on confirmed attacks.

---

## Release Directory Structure

* [`setup-instructions.md`](./setup-instructions.md) — Local installation, environment variables, and execution commands.
* [`agent-status-report.md`](./agent-status-report.md) — Status, contracts, and telemetry for all five agents.
* [`test-report.md`](./test-report.md) — Automated pytest and TypeScript build verification results.
* [`model-verification-report.md`](./model-verification-report.md) — Verified metrics, training scopes, and feature schema.
* [`replay-report.md`](./replay-report.md) — Replay throughput (6,712 FPS) and official 114k holdout statistics.
* [`csv-validation-report.md`](./csv-validation-report.md) — Integrity report for the 3 submission CSV files.
* [`system-walkthrough.md`](./system-walkthrough.md) — Step-by-step panel walkthrough.
* [`known-limitations.md`](./known-limitations.md) — Explicit boundary disclosures.

