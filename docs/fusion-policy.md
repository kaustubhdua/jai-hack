# CyberSentinel: Evidence Fusion Policy Specification

**Component:** Agent 3 (`src/cybersentinel/agents/fusion.py`)  
**Design Principle:** Deterministic, explainable, fail-safe consensus without blind overrides.  

---

## 1. Decision Matrix & Operational Scenarios

The Evidence Fusion Agent evaluates all incoming signals against 11 deterministic security scenarios:

| # | Operational Scenario | Agent 1 (Threat) | Agent 2 (Anomaly) | Decision Status | Policy Action | Explainable Rationale |
|---|---|---|---|---|---|---|
| **1** | **Normal Traffic Agreement** | `BENIGN` (Conf >= 0.60) | Not Anomaly (`False`) | `AGREE` | **ALLOW** | Both agents corroborate normal baseline network behavior. |
| **2** | **Confirmed Attack Agreement** | Attack class (Conf >= 0.85) | Anomaly (`True`) | `AGREE` | **BLOCK** | Dual consensus: signature confirmed and corroborated by statistical deviation. |
| **3** | **Stealth / Low-Volume Attack** | Attack class (Conf >= 0.85) | Not Anomaly (`False`) | `DISAGREE` | **BLOCK** | High confidence signature match overrides statistical silence typical of slow probes. |
| **4** | **Potential Zero-Day Exploit** | `BENIGN` | Anomaly (`True`) | `DISAGREE` | **REVIEW** | Uncatalogued threat vector or rare protocol spike; held for analyst inspection. |
| **5** | **Attack Discrepancy** | Attack class (0.60 <= Conf < 0.85) | Not Anomaly (`False`) | `DISAGREE` | **REVIEW** | Borderline attack confidence without anomaly backing triggers human verification. |
| **6** | **Agent 1 Failure** | Error / Unavailable | Valid score | `INCOMPLETE` | **REVIEW** | Degraded mode; falls back to anomaly signal with cautious analyst hold. |
| **7** | **Agent 2 Failure** | Valid prediction | Error / Unavailable | `INCOMPLETE` | **BLOCK / ALLOW** | Fallback to Agent 1 with elevated confidence requirement (Conf >= 0.85). |
| **8** | **Both Agents Fail** | Error / Unavailable | Error / Unavailable | `INCOMPLETE` | **REVIEW** | Failsafe security posture; defaults to simulated REVIEW. |
| **9** | **Low Classifier Confidence** | Conf < 0.60 | Any | `AGREE / DISAGREE` | **REVIEW** | Prediction uncertainty triggers manual review rather than automatic action. |
| **10**| **Missing Anomaly Score** | Valid prediction | Score is `None` | `INCOMPLETE` | **REVIEW** | Missing metric calculation flags incomplete evidence. |
| **11**| **Invalid Flow Input** | Empty / Non-dict | Empty / Non-dict | `INCOMPLETE` | **REVIEW** | Input sanitization rejection. |

---

## 2. Threshold Calibration

- **High Confidence Threshold (`0.85`):** Required for supervised single-agent block overrides during anomaly silence.
- **Low Confidence Threshold (`0.60`):** Below this floor, supervised predictions are deemed uncertain.
- **Anomaly Score Threshold (`-0.0232`):** Defensible threshold determined from the 1st percentile of normal training traffic, guaranteeing an evaluation false positive rate of 0.52%.

---

## 3. Transparency & Explanations

Every decision emits an array of `rationale` strings recording:
- Agent 1 class and confidence
- Agent 2 score and anomaly determination
- Concrete feature deviations (e.g. `unusual_packet_rate: Flow Packets/s > Q99`)
- Exact policy reason for `ALLOW`, `BLOCK`, or `REVIEW`.
