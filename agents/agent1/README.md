# CyberSentinel Agent 1 — supervised threat detection

Reproducible scikit-learn baseline using `HistGradientBoostingClassifier`.

- Training input: user-provided `train (2).csv`, 288,750 rows (incomplete vs. official training count 456,737).
- Features: 75 numeric flow features; excludes `label`, `record_id`, all-null and constant columns.
- Preprocessing: numeric coercion, infinities to missing, median imputation; balanced sample weights.
- Validation: 80/20 `GroupShuffleSplit` grouped by exact feature-row hash, preventing identical feature vectors crossing partitions.
- Internal grouped holdout: accuracy **0.999948**, macro-F1 **0.999965** (57,680 rows).
- Duplicate feature rows: 19,294; conflicting labels among identical feature vectors: 0.

These are internal metrics on an incomplete training export, not official benchmark or real-world performance. The organiser's untouched evaluation set was not available for this run.

## Run
```bash
pip install pandas numpy scikit-learn joblib
python train_agent1.py --train path/to/train.csv --out artifacts
python predict_agent1.py --model artifacts/threat_detection_model.joblib --input flows.csv --output predictions.csv
```

The trained binary is supplied in the companion artifact bundle and is not committed to Git.
