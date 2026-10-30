# Agent 1 — Supervised Threat Detection

*Member 2 owns this supervised-learning workstream.*

## Installation

```bash
pip install -e ".[dev,ml]"
```

Optional XGBoost experiment:
```bash
pip install -e ".[ml,xgboost]"
```

## Label Mapping

If the data already uses canonical classes (`BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, `PORT_SCAN`), no mapping file is needed. If raw attack labels are used, pass `--label-map` with the exact organiser JSON mapping. No guessed attack mappings are performed.

## Training Commands

### 1. Training on Prepared Parquet (Canonical Challenge Split)
```bash
python -m cybersentinel.agents.threat_detection.train \
  --train data/processed/training_prepared.parquet \
  --label-column label \
  --model-out models/threat_detection/model.joblib \
  --report-out reports/generated/agent1-training.json
```

### 2. CSV Training & Evaluation
```bash
python -m cybersentinel.agents.threat_detection.train \
  --train-csv data/raw/train.csv \
  --label-column Label \
  --label-map data/raw/organiser-label-map.json \
  --validation-csv data/raw/validation.csv \
  --model-out models/threat_detection/model.joblib \
  --report-out reports/generated/threat_detection_training.json
```

## Batch Inference Entry Point

```bash
python -m cybersentinel.agents.threat_detection.predict_cli \
  --model models/threat_detection/model.joblib \
  --input-csv data/raw/unlabelled-flows.csv \
  --output-csv reports/generated/threat_predictions.csv
```

Or via direct script:
```bash
python agents/agent1/predict_agent1.py \
  --model models/threat_detection/model.joblib \
  --input data/raw/unlabelled-flows.csv \
  --output predictions.csv
```

## Verified Holdout Performance (114,185 Flows)

- **Accuracy:** 99.9956%
- **Macro-F1:** 0.999897
- **Macro-Precision:** 0.999983
- **Macro-Recall:** 0.999811
- **Per-Class F1:**
  - `BENIGN`: 0.999958 (Support: 60,001)
  - `BRUTE_FORCE`: 0.999639 (Support: 1,384)
  - `DOS`: 0.999958 (Support: 24,000)
  - `DDOS`: 1.000000 (Support: 14,400)
  - `PORT_SCAN`: 0.999931 (Support: 14,400)

## Design & Hygiene Controls

- Flow ID, source/destination IP, and timestamp identifiers are excluded to reduce memorization and shortcut learning.
- Numeric flow measurements and destination ports remain eligible.
- Missing and infinite values are median-imputed using training data statistics only.
- Preprocessing and feature selection are fitted strictly on training data; evaluation data is strictly holdout.


## Confidence calibration

The raw Random Forest/XGBoost `predict_proba` output is not automatically calibrated. The model therefore records `confidence_calibrated=false` after ordinary training. To calibrate, call `calibrate_confidence(validation_features, validation_labels)` with a separate labelled validation partition containing all five benchmark classes. This fits scalar temperature scaling against validation negative log-likelihood, persists the temperature and validation provenance, and applies the same transformation at inference. Never use hidden evaluation labels for calibration. Report calibration status and validation metrics; a calibrated confidence remains a model estimate, not a guarantee.
