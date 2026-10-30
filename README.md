# CyberSentinel

**JAI 2026 · Track 1: Agentic AI for Cybersecurity**

CyberSentinel is an offline multi-agent network intrusion detection and adaptive defense system built on official CICIDS2017 flow data. The system combines supervised threat classification, independent unsupervised anomaly detection, and a deterministic evidence fusion engine to generate transparent, explainable recommendations and simulated `ALLOW`, `BLOCK`, and `REVIEW` actions.

> **Operational Scope & Safety:** Strict offline dataset analysis and traffic replay challenge. No unauthorized packet interception, live network attacks, or real firewall modifications. All policy actions are simulated recommendations.

---

## 1. System Architecture

CyberSentinel features a coordinated tri-agent intelligence framework:

```
                  ┌────────────────────────────────────────┐
                  │          Incoming Flow Vector          │
                  │   (71 train-fitted numeric features)   │
                  └───────────────────┬────────────────────┘
                                      │
            ┌─────────────────────────┴─────────────────────────┐
            ▼                                                   ▼
┌───────────────────────────────┐               ┌───────────────────────────────┐
│  Agent 1: Threat Detection    │               │  Agent 2: Anomaly Detection   │
│  Supervised Random Forest     │               │  Unsupervised Isolation Forest│
│  5 Benchmark Classes          │               │  Fitted on Normal (BENIGN)    │
│  Output: Class + Confidence   │               │  Output: Score + Real Evidence│
└───────────────┬───────────────┘               └───────────────┬───────────────┘
                │                                               │
                └───────────────────────┬───────────────────────┘
                                        │
                                        ▼
                        ┌───────────────────────────────┐
                        │   Agent 3: Evidence Fusion    │
                        │   Deterministic Decision Tree │
                        │   Agreement, Disagreement,    │
                        │   Low Confidence & Failures   │
                        │   Output: ALLOW, BLOCK, REVIEW│
                        └───────────────┬───────────────┘
                                        │
                                        ▼
                        ┌───────────────────────────────┐
                        │  Explainable Decision Output  │
                        │  Full Audit Trail & Rationale │
                        └───────────────────────────────┘
```

1. **Agent 1 (Threat Detection Agent):** Supervised multiclass classifier trained on 456,737 flows. Predicts the 5 official benchmark classes (`BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, `PORT_SCAN`) and reports model-derived confidence. (See [`docs/AGENT1.md`](docs/AGENT1.md) and [`agents/agent1/`](agents/agent1/)).
2. **Agent 2 (Anomaly Detection Agent):** Independent unsupervised baseline detector trained solely on 240,000 `BENIGN` flows. Calculates anomaly scores against a calibrated threshold (`-0.0232`), evaluates benign false positive rates (0.52%), and generates concrete feature attribution evidence (e.g. `unusual_packet_rate`, `abnormal_flow_duration`).
3. **Agent 3 (Evidence Fusion Agent):** Deterministic consensus and policy engine. Handles full agreement, stealth attacks, zero-day anomalies, low confidence scenarios, and agent failures without crashing.

Shared contracts are defined in `src/cybersentinel/contracts.py`. Pipeline orchestration is implemented in `src/cybersentinel/pipeline.py`.

---

## 2. Dataset & Quality Findings

Official archive: `cyber-pack.zip` (CICIDS2017 Parquet). Full findings and diagnostics are detailed in [`docs/data-intelligence.md`](docs/data-intelligence.md) and [`docs/day1-progress-questionnaire.md`](docs/day1-progress-questionnaire.md).

| Split | Location | Rows | Features | Target Column |
|---|---|---:|---:|---|
| **Training** | `Cyber/training/flows.parquet` | 456,737 | 71 (pruned from 78) | `label` |
| **Evaluation Holdout** | `Cyber/eval/flows.parquet` | 114,185 | 71 (pruned from 78) | `label` |

### Benchmark Class Distribution

| Class | Training Rows | Training % | Eval Rows | Eval % | Total | Proportion |
|---|---:|---:|---:|---:|---:|---:|
| `BENIGN` | 240,000 | 52.55% | 60,001 | 52.55% | 300,001 | 52.55% |
| `BRUTE_FORCE` | 5,537 | 1.21% | 1,384 | 1.21% | 6,921 | 1.21% |
| `DOS` | 96,000 | 21.02% | 24,000 | 21.02% | 120,000 | 21.02% |
| `DDOS` | 57,600 | 12.61% | 14,400 | 12.61% | 72,000 | 12.61% |
| `PORT_SCAN` | 57,600 | 12.61% | 14,400 | 12.61% | 72,000 | 12.61% |

### Data Hygiene & Leakage Prevention
- **Sequential ID Leakage Avoidance:** `record_id` clusters sequential labels (leakage diagnostic: 69.1% accuracy). It is strictly excluded from all training and inference matrices.
- **Redundant Column Pruning:** 3 constant zero columns (`Fwd URG Flags`, `Bwd URG Flags`, `URG Flag Count`) and 4 duplicate columns (`Average Packet Size`, `Avg Fwd Segment Size`, `Avg Bwd Segment Size`, `Fwd Header Length_duplicated_0`) were identified on training data and removed.
- **Imputation Integrity:** 37 training and 10 eval flows with negative header lengths are sanitized and imputed using training-only medians.

---

## 3. Official Evaluation Holdout Performance

Evaluated strictly on the held-out 114,185 official evaluation flows:

| Benchmark Metric | Measured Result | Benchmark Standard | Status |
|---|---|---|---|
| **Overall Accuracy** | **99.9965%** | > 95% | **Exceeds** |
| **Macro-F1 Score** | **0.999971** | > 0.90 | **Exceeds** |
| **Macro Precision** | **0.999987** | > 0.90 | **Exceeds** |
| **Macro Recall** | **0.999956** | > 0.90 | **Exceeds** |
| **Benign False Positive Rate** | **0.0000%** | < 1% | **Optimal** |
| **Attack False Negative Rate** | **0.0074%** | < 1% | **Optimal** |
| **Agent 1 Inference Latency** | **0.007 ms/flow** | < 1.0 ms | **High-Throughput** |
| **Agent 2 Inference Latency** | **0.010 ms/flow** | < 1.0 ms | **High-Throughput** |

Confusion matrix and detailed audit reports available in:
- `reports/model_evaluation.md`
- `reports/metrics.json`
- `reports/confusion_matrix.png`
- `reports/dataset_audit.md`
- `reports/data_quality_report.json`

---

## 4. Application & Deployment Stack

- **Frontend:** React 19 + TypeScript + Vite + modern dark SOC UI, deployed on Vercel.
- **Backend API:** FastAPI (Python 3.14) on Vercel Functions.
- **Authentication & Audit Trail:** Supabase Auth + Postgres with Row-Level Security (RLS).
- **Offline ML Pipeline:** NumPy, Pandas, Scikit-learn, PyArrow, Joblib.

---

## 5. API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service status, model artifact readiness, and agent states |
| `GET` | `/api/models/status` | Model architectures, backend types, thresholds, and training metadata |
| `POST` | `/api/analyze` | Single network flow analysis returning full 3-agent fusion result |
| `POST` | `/api/analyze/batch` | Batch flow analysis (up to 1,000 flows) with decision summary |
| `GET` | `/api/metrics` | Measured holdout evaluation metrics and per-class performance |
| `GET` | `/api/dataset/summary` | Official CICIDS2017 schema and class distribution figures |
| `GET` | `/api/history` | Ephemeral audit runs and historical run telemetry |

---

## 6. Local Setup & Testing

### Prerequisites
- Node.js 20+
- Python 3.10+ (tested on Python 3.14)

### 1. Frontend Setup
```bash
npm install
cp .env.example .env.local  # Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY if using Supabase
npm run build
npm run dev
```

### 2. Python Environment Setup
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev,ml]"
```

### 3. Run Automated Tests
```bash
pytest
```
*Executes all 27 automated tests covering data loading, cleaning, threat prediction, anomaly scoring, evidence extraction, fusion agreement/disagreement, and API validation.*

### 4. Run Model Training & Evaluation (Offline)
```bash
# 1. Dataset profiling and train-fitted preprocessing
python -m cybersentinel.data.cleaning --train data/raw/training/flows.parquet --eval data/raw/eval/flows.parquet --out-dir data/processed

# 2. Train Agent 1 (Threat Detection)
python scripts/train_agent1.py

# 3. Train Agent 2 (Anomaly Detection)
python scripts/train_agent2.py

# 4. Run official holdout evaluation and generate reports
python scripts/evaluate_models.py
```

---

## 7. Team Ownership & Attribution

| Workstream | Owner | Main Paths |
|---|---|---|
| **Data Engineering & Profiling** | Member 1 | `src/cybersentinel/data/`, `docs/data-intelligence.md` |
| **Supervised Threat Detection** | Member 2 | `src/cybersentinel/agents/threat_detection/`, `agents/agent1/`, `docs/AGENT1.md` |
| **Independent Anomaly Detection** | Member 3 | `src/cybersentinel/agents/anomaly_detection.py` |
| **Evidence Fusion & Integration Lead** | Team Lead / Integrator | `src/cybersentinel/agents/fusion.py`, `pipeline.py`, `api/`, `src/App.tsx`, `supabase/` |
