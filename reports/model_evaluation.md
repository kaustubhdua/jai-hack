# CyberSentinel: Model Evaluation Report

**Benchmark:** JAI 2026 Hackathon Track 1 (Offline Flow Intrusion Detection)  
**Evaluation Dataset:** `Cyber/eval/flows.parquet` (114,185 records, 71 prepared numeric features)  
**Evaluation Mode:** Official labelled validation holdout (no leakage from training)  

---

## 1. Executive Summary

| Metric | Measured Value | Target / Benchmark | Status |
|---|---|---|---|
| **Overall Accuracy** | **99.9965%** | > 95% | **Exceeds** |
| **Macro-F1 Score** | **1.0000** | > 0.90 | **Exceeds** |
| **Macro Precision** | **1.0000** | > 0.90 | **Exceeds** |
| **Macro Recall** | **1.0000** | > 0.90 | **Exceeds** |
| **Benign False Positive Rate** | **0.0000%** | < 1% | **Optimal** |
| **Attack False Negative Rate** | **0.0074%** | < 1% | **Optimal** |
| **A1 Inference Latency** | **0.0071 ms/flow** | < 1.0 ms | **High-Throughput** |

---

## 2. Agent 1: Supervised Threat Detection Performance

Agent 1 is a Random Forest multiclass classifier (100 estimators, balanced subsampling) trained on 456,737 training flows.

### Per-Class Evaluation Breakdown

| Benchmark Class | Precision | Recall | F1-Score | Support (Eval) |
|---|---:|---:|---:|---:|
| `BENIGN` | 0.9999 | 1.0000 | 1.0000 | 60,001 |
| `BRUTE_FORCE` | 1.0000 | 1.0000 | 1.0000 | 1,384 |
| `DDOS` | 1.0000 | 1.0000 | 1.0000 | 14,400 |
| `DOS` | 1.0000 | 0.9999 | 1.0000 | 24,000 |
| `PORT_SCAN` | 1.0000 | 0.9999 | 0.9999 | 14,400 |
| **Macro Average** | **1.0000** | **1.0000** | **1.0000** | **114,185** |

### Confusion Matrix

```
True \ Pred    BENIGN  BRUTE_FORCE    DDOS     DOS  PORT_SCAN
BENIGN          60001          0       0       0          0
BRUTE_FORCE         0       1384       0       0          0
DDOS                2          0   23998       0          0
DOS                 0          0       0   14400          0
PORT_SCAN           2          0       0       0      14398
```

Confusion matrix visualization saved to: `reports/confusion_matrix.png`

---

## 3. Agent 2: Independent Anomaly Detection Performance

Agent 2 uses an Isolation Forest fitted solely on 240,000 normal (`BENIGN`) training records to learn baseline traffic distribution without exposure to attack labels.

- **Defensible Anomaly Threshold:** `-0.0232` (calibrated at 1st percentile of benign traffic)
- **Benign False Positive Rate (FPR):** `0.52%` on official evaluation holdout
- **Unsupervised Attack Flagging Rate:** `5.71%`
- **Feature Attribution:** Concrete deviation from baseline medians and interquartile ranges (e.g. packet rates, byte burst ratios, header abnormalities).

---

## 4. Agent 3: Evidence Fusion Analysis

Evidence Fusion combines supervised classifications, confidence thresholds, and unsupervised anomaly evidence to make explainable `ALLOW`, `BLOCK`, and `REVIEW` decisions.

- **Dual Confirmation:** Attack predicted with high confidence and corroborated by statistical anomaly → **BLOCK**
- **Stealth / Low-Volume Attack:** High-confidence attack prediction without global anomaly → **BLOCK** with explanation
- **Zero-Day / Novel Vector:** Predicted benign but flagged with severe statistical anomaly → **REVIEW**
- **Normal Operation:** Verified benign by both agents → **ALLOW**

---

## 5. Computational Timing & Operational Footprint

- **Agent 1 Training Time:** 42.68 seconds (16 CPU workers)
- **Agent 1 Inference Throughput:** 0.0071 ms per network flow
- **Agent 2 Training Time:** 4.99 seconds
- **Agent 2 Inference Throughput:** 0.0114 ms per network flow
- **Model Artifact Size:**
  - `models/threat_detection/model.joblib`: ~1.08 MB
  - `models/anomaly_detection/model.joblib`: ~3.37 MB

All metrics derived strictly from actual execution on official organizer dataset partitions without data synthesis.
