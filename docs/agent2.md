# Agent 2: Independent Anomaly Detection

## Architecture & Algorithm

- **Model:** Isolation Forest (200 trees, 50,000 max samples per tree, `n_jobs=-1`).
- **Baseline Training Data:** `BENIGN` rows from the model-fit subset of the authorized training partition. The exact count and data hash are recorded in `reports/generated/training_manifest.json`.
- **Independence:** Never ingests or depends on Agent 1 predictions or ground truth labels during inference.
- **Threshold Calibration:** The default operating threshold is derived from the BENIGN training-score distribution. Label-based threshold tuning is disabled by default; it requires an explicitly permitted separate labelled validation file and the `--calibrate-anomaly-threshold` opt-in flag.
- **Evidence Extraction:** For flows whose raw decision-function score falls below the threshold, individual features deviating beyond $Q_{01}$ or $Q_{99}$ relative to benign training interquartile ranges are mapped to human-readable evidence tags (e.g., `unusual_packet_rate`, `abnormal_flow_duration`).

## Exported score semantics

The CSV/API exports a bounded 0–1 anomaly index derived from the Isolation Forest decision function; higher values mean more anomalous. It is **not** a calibrated probability of attack. The operating threshold is applied to the underlying decision function, not interpreted as a probability cutoff.

## Training Command

```bash
python scripts/train_anomaly.py \
  --train data/processed/training_prepared.parquet \
  --model-out models/anomaly_detection/model.joblib \
  --report-out reports/generated/agent2-training.json
```

## Evaluation Status

No current official-evaluation FPR, attack recall, or latency result is reproducible from this repository alone because the evaluation data and trained model artifact are not committed. Older release reports contain different values; treat them as historical and do not cite them as current.

The standalone `train_anomaly.py` command is a lower-level training entry point. For the supported combined workflow (including the training-only calibration holdout), use `scripts/train_models.py`. Evaluate the saved artifacts against the untouched evaluation split and retain the report with the code revision and dataset hashes. See [`docs/evaluation.md`](evaluation.md).
