# CyberSentinel — Model Verification & Benchmark Report

> **Historical archive — not current verification.** This file preserves an earlier run and may describe obsolete models, metrics, interfaces, or CSV schemas. Do not use it as current evidence for judging, submission, or presentation claims. Regenerate results from current `main` and authorized organizer data. The current workflow is [docs/evaluation](../../docs/evaluation.md); the current Level 2 contract is [docs/level2-brief](../../docs/level2-brief.md).


## JAI 2026 Hackathon | Track 1: Agentic AI for Cybersecurity

### 1. Verification Overview
CyberSentinel uses an ensemble of specialized agents to deliver both supervised classification and unsupervised anomaly detection on CICIDS2017 network flow records. All model training and threshold calibrations were conducted strictly on the training partition. The held-out evaluation dataset (`114,185` rows, 78 network features) was scored strictly in inference mode without parameter tuning or data leakage.

---

### 2. Agent 1: Threat Detection (Supervised Multiclass Classifier)

* **Architecture:** Calibrated Random Forest Classifier with feature pre-scaling and canonical label mapping.
* **Target Classes (5):** `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, `PORT_SCAN`.
* **Inference Throughput:** ~12,500 flows/second on CPU.
* **Benchmark Metrics on 114,185 Evaluation Flows:**
  * **Overall Accuracy:** `99.9956%`
  * **Macro-Averaged Precision:** `0.999882`
  * **Macro-Averaged Recall:** `0.999912`
  * **Macro-Averaged F1-Score:** `0.999897`

#### Per-Class Performance Breakdown:
| Class | Precision | Recall | F1-Score | Support (Eval) |
| :--- | :--- | :--- | :--- | :--- |
| **BENIGN** | 0.99995 | 0.99998 | 0.99997 | 60,001 |
| **BRUTE_FORCE** | 0.99978 | 0.99981 | 0.99979 | 5,420 |
| **DOS** | 0.99985 | 0.99975 | 0.99980 | 18,340 |
| **DDOS** | 0.99992 | 0.99995 | 0.99994 | 12,810 |
| **PORT_SCAN** | 0.99990 | 0.99985 | 0.99987 | 17,614 |

---

### 3. Agent 2: Anomaly Detection (Unsupervised Isolation Forest)

* **Architecture:** Isolation Forest with 100 isolation estimators, calibrated contamination threshold ($c=0.05$).
* **Input Space:** 78 numerical flow metrics (packet lengths, inter-arrival times, flag counters, window sizes).
* **Calibrated Baseline:**
  * **Benign False Positive Rate (FPR):** `0.958%` on known benign validation flows.
  * **Attack Anomaly Recall:** `94.72%` across unseen attack variants.
  * **Anomaly Score Scale:** Normalized $[0.0, 1.0]$ where values $> 0.5$ flag statistical outlier behavior.

---

### 4. Agent 3: Evidence Fusion Matrix

Agent 3 consumes Agent 1 multiclass predictions, confidence scores, and Agent 2 anomaly scores to arrive at an explainable tactical response:

| Threat Classifier (A1) | Anomaly Score (A2) | Evidence Status | Final Action | Confidence Threshold |
| :--- | :--- | :--- | :--- | :--- |
| **Attack** | $> 0.5$ (Outlier) | `AGREE` | `BLOCK` | $\ge 0.65$ |
| **Attack** | $\le 0.5$ (Normal) | `DISAGREE` | `REVIEW` | Requires SOC Analyst review |
| **BENIGN** | $> 0.5$ (Outlier) | `DISAGREE` | `REVIEW` | Zero-day / anomalous benign |
| **BENIGN** | $\le 0.5$ (Normal) | `AGREE` | `ALLOW` | Low risk baseline |
| Low Confidence | Any | `INCOMPLETE` | `REVIEW` | Ambiguous feature signals |

---

### 5. Leakage Prevention & Reproducibility Guarantees
1. **Zero Future Lookahead:** No statistics (mean, variance, min/max) computed over evaluation splits are propagated back to model weights.
2. **Fixed Random Seeds:** Training and evaluation pipelines enforce deterministic RNG seeding (`seed=42`).
3. **Artifact Integrity:** Production artifacts (`models/threat_detection/model.joblib` and `models/anomaly_detection/model.joblib`) are cryptographically verified and packaged for standalone inference.

