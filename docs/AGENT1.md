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

For the supported combined A1/A2 workflow, use `python scripts/train_models.py --train data/raw/training/flows.parquet`. It creates a deterministic stratified calibration holdout from the authorized training partition by default, fits A1 on the remaining rows, and records calibration provenance. The lower-level commands below are for isolated agent development and reproduction.

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

## Available Training Evidence

The checked-in report at `agents/agent1/training_report.json` describes a **standalone HistGradientBoosting experiment**, not the production model in `src/cybersentinel/agents/threat_detection/`. It used an incomplete 288,750-row training export and a grouped internal holdout:

- Accuracy: `0.999948`
- Macro-F1: `0.999965`

These are internal experiment results, not scores on the organizer's official evaluation set. The production module defaults to Random Forest; no current official-evaluation score should be quoted until a fresh run is made with the complete authorized data and the production model.

## Design & Hygiene Controls

- Flow ID, source/destination IP, and timestamp identifiers are excluded to reduce memorization and shortcut learning.
- Numeric flow measurements and destination ports remain eligible.
- Missing and infinite values are median-imputed using training data statistics only.
- Preprocessing and feature selection are fitted strictly on training data; evaluation data is strictly holdout.
