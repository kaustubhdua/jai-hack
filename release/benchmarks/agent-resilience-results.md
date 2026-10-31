# CyberSentinel — Five-Agent Architecture & Adversarial Test Map (Corrected)

> **Historical archive — not current verification.** This file preserves an earlier run and may describe obsolete models, metrics, interfaces, or CSV schemas. Do not use it as current evidence for judging, submission, or presentation claims. Regenerate results from current `main` and authorized organizer data. The current workflow is [docs/evaluation](../../docs/evaluation.md); the current Level 2 contract is [docs/level2-brief](../../docs/level2-brief.md).


**Status:** Corrected role mapping based on current source code and the official Day 2 brief. Test results must be taken from the latest CI run, not copied from this historical report.

## Official agent responsibilities

| Agent | Required responsibility | Current implementation |
|---|---|---|
| A1 | Supervised five-class threat detection | `ThreatDetectionAgent` / `ThreatDetectionModel`; source implementation uses scikit-learn RandomForest by default. |
| A2 | Independent anomaly detection | `AnomalyDetectionAgent`; Isolation Forest model and anomaly evidence. |
| A3 | Evidence fusion | `EvidenceFusionAgent`; combines A1 and A2, records the current evidence states `AGREE`, `CONFLICT`, or `UNCERTAIN` and rationale. |
| A4 | Temporal correlation | `TemporalCorrelationAgent`; sliding-window grouping using observed endpoints, ports and record order. |
| A5 | Adaptive defense | `AdaptiveDefenseAgent`; simulated temporary ALLOW/BLOCK policy lifecycle, activation and expiry. |

**Important correction:** Earlier copies of this dossier incorrectly assigned temporal correlation to A3, policy management to A4, and an incident reporter to A5. That role mapping contradicts the official brief and the current implementation. The five rows above are authoritative.

## A1 — Threat Detection

Source: `src/cybersentinel/agents/threat_detection/model.py`

- Five allowed classes: `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, `PORT_SCAN`.
- Numeric feature conversion removes identifier-like columns and replaces non-finite values with missing values before imputation.
- The source default backend is RandomForest; optional XGBoost is a separate backend.
- The combined trainer temperature-calibrates A1 confidence on its default stratified holdout drawn from the training partition. If calibration is disabled with `--calibration-fraction 0`, the raw maximum `predict_proba` value is uncalibrated. The evaluation partition must not be used for calibration.
- Model artifact availability and metadata must be checked at runtime.

Adversarial coverage should include missing/non-finite features, unexpected columns, feature ordering, invalid labels, artifact absence/corruption and model inference failures.

## A2 — Anomaly Detection

Source: `src/cybersentinel/agents/anomaly_detection.py`

A2 must run independently of A1 and return a score, flag, status and evidence. Score interpretation must follow the actual artifact's scoring convention; do not convert it to a probability without calibration.

Adversarial coverage should include NaN/Inf, missing values, extreme values, invalid artifacts, threshold boundaries and benign false-positive measurement.

## A3 — Evidence Fusion

Source: `src/cybersentinel/agents/fusion.py`

The production fusion contract is authoritative. It validates both agent outputs, routes incomplete evidence to REVIEW, routes disagreement to REVIEW, and uses the configured high-confidence gate for corroborated attack/benign recommendations.

The frontend workbench now calls `POST /api/fusion/simulate`, which invokes this Python implementation. Do not maintain a separate frontend decision matrix.

## A4 — Temporal Correlation

Source: `src/cybersentinel/agents/correlation.py`

The agent maintains a bounded sliding history and corresponding source/port and destination/source counters. It emits group IDs, observed member IDs, endpoints and evidence.

Adversarial coverage should include counter eviction, duplicate ports, interleaved sources, empty endpoint metadata, benign traffic, port-scan thresholds, DDoS convergence and authentication bursts.

## A5 — Adaptive Defense

Source: `src/cybersentinel/agents/adaptive_defense.py`

The agent checks previously activated policies before allowing a new record into the analysis path. A newly created policy is forward-looking; the triggering record must remain ALLOW. Policies are simulated in application memory and never alter the host firewall.

Adversarial coverage should include exact activation/expiry boundaries, non-matching endpoints, duplicate policy attempts, overlapping policy cases, empty identity and valid policy references.

## Replay-level acceptance invariants

Source: `src/cybersentinel/replay/engine.py`

- Records retain supplied order.
- Existing active policies are checked before the per-record action decision.
- Classification output is retained for every record, including records blocked by an earlier policy.
- The triggering record is not blocked by its own policy.
- Under the current stage-page contract, BLOCK references an applicable active policy; ALLOW uses `active_policy_id=NONE`. This differs from the earlier handout wording.
- Ground-truth labels are used only for offline evaluation metrics, never for inference or policy decisions.

## Test evidence

Relevant suites include:

- `tests/test_threat_detection.py`
- `tests/test_anomaly_detection.py`
- `tests/test_fusion.py`
- `tests/test_correlation.py`
- `tests/test_adaptive_defense.py`
- `tests/test_replay.py`
- `tests/test_adversarial_agents.py`
- `tests/test_api.py`

The latest CI result for the corrected branch is the source of truth for pass/fail counts. Do not reuse the previous 60-test result after code changes without rerunning the suite.
