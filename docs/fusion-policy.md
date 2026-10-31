# Agent 3: Evidence Fusion Policy

## Policy Decision Table

Agent 3 fuses independent evidence from Agent 1 and Agent 2 using a deterministic, explainable expert consensus matrix:

| Condition | Threat Agent (A1) | Anomaly Agent (A2) | Evidence Status | Simulated Action | Policy Rationale |
|---|---|---|:---:|:---:|---|
| **Benign Agreement** | `BENIGN` ($C \ge 0.85$) | Not Anomalous ($S \ge \theta$) | `AGREE` | `ALLOW` | Both agents agree traffic matches baseline normal behavior. |
| **Attack Agreement** | Attack Class ($C \ge 0.85$) | Anomalous ($S < \theta$) | `AGREE` | `BLOCK` | High-confidence attack signature confirmed by independent statistical anomaly. |
| **Low Confidence** | Any Class ($C < 0.85$) | Any Output | Depends | `REVIEW` | Insufficient classifier confidence requires operator triage. |
| **Disagreement** | `BENIGN` ($C \ge 0.85$) | Anomalous ($S < \theta$) | `CONFLICT` | `REVIEW` | Potential zero-day exploit or stealth anomaly; flagged for investigation. |
| **Disagreement** | Attack Class ($C \ge 0.85$) | Not Anomalous ($S \ge \theta$) | `CONFLICT` | `REVIEW` | Signature alert with baseline metrics requires human analyst verification. |
| **Incomplete / Error** | Crashed or Invalid | Crashed or Invalid | `UNCERTAIN` | `REVIEW` | Fails closed to prevent unauthorized pass-through. |

## Safety & Scope Disclosure

All actions (`ALLOW`, `BLOCK`, `REVIEW`) are simulated recommendations for offline network flow analysis and replay. The software does not interact with physical firewalls, kernel tables, or live network devices.
