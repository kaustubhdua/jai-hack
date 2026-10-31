# CyberSentinel — Agent Status Report

> **Historical archive — not current verification.** This file preserves an earlier run and may describe obsolete models, metrics, interfaces, or CSV schemas. Do not use it as current evidence for judging, submission, or presentation claims. Regenerate results from current `main` and authorized organizer data. The current workflow is [docs/evaluation](../../docs/evaluation.md); the current Level 2 contract is [docs/level2-brief](../../docs/level2-brief.md).


| Agent | Module | Input Contract | Output Contract | Verification Status |
| :--- | :--- | :--- | :--- | :--- |
| **Agent 1: Threat Detection** | `src/cybersentinel/agents/threat_detection/` | 71 numeric flow features | `predicted_class`, `confidence` | **OPERATIONAL** (Model: `models/threat_detection/model.joblib`) |
| **Agent 2: Anomaly Detection** | `src/cybersentinel/agents/anomaly_detection.py` | 71 numeric flow features | `anomaly_score`, `is_anomaly`, `evidence` | **OPERATIONAL** (Model: `models/anomaly_detection/model.joblib`) |
| **Agent 3: Evidence Fusion** | `src/cybersentinel/agents/fusion.py` | A1 output, A2 output | `final_class`, `evidence_status`, `action`, `rationale` | **OPERATIONAL** (Deterministic 6-scenario matrix) |
| **Agent 4: Temporal Correlation** | `src/cybersentinel/agents/correlation.py` | Current flow, endpoints, sliding history | `group_id`, `attack_type`, `group_size`, `evidence` | **OPERATIONAL** (Sliding window buffer, pattern detection) |
| **Agent 5: Adaptive Defense** | `src/cybersentinel/agents/adaptive_defense.py` | Flow endpoints, pipeline decisions | `action`, `applied_policy_id`, `new_policy` | **OPERATIONAL** (Pre-filtering + forward policy generation) |

---

## Agent Communication & Causal Data Flow

```text
Incoming Flow (record_id = N, Source IP = X)
               │
               ▼
[Agent 5: Pre-Filter] ── Active Policy Matches X? ──► [YES] ──► Action: BLOCK (applied_policy_id = POL-XXXXX)
               │ [NO]                                            (0ms ML inference overhead)
               ▼
   [Agent 1: Classifier]  ──► (predicted_class, confidence)
   [Agent 2: Isolation]   ──► (anomaly_score, is_anomaly, evidence)
               │
               ▼
   [Agent 3: Evidence Fusion] ──► (final_class, evidence_status, action, rationale)
               │
               ▼
   [Agent 4: Temporal Correlation] ──► (group_id, attack_type, group_size, evidence)
               │
               ▼
   [Agent 5: Policy Generator] ──► Confirmed Attack? ──► [YES] ──► Create Policy for LATER records (POL-YYYYY)
                                                         [NO]  ──► Action: ALLOW (applied_policy_id = "")
```

