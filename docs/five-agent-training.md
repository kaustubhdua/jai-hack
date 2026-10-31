# Five-agent training and verification

CyberSentinel has **two learned detection models** and **three deterministic response agents**. Do not describe Agents 3–5 as machine-learning models that need dataset training.

## Agent 1 — supervised threat detection

Train the five-class Random Forest with the repository's trainer:

```bash
python -m cybersentinel.agents.threat_detection.train --train data/processed/training_prepared.parquet --label-column label --model-out models/threat_detection/model.joblib
```

Use a separate labelled validation split with `--validation` and `--validation-label-column label` where available. Do not use `record_id` as a feature. The model requires all five canonical labels.

## Agent 2 — benign-baseline anomaly detection

Train from the official training partition only. The trainer selects BENIGN rows itself; it never trains on attack rows:

```bash
python -m cybersentinel.agents.anomaly_detection.train --train data/processed/training_prepared.parquet --validation data/processed/eval_prepared.parquet
```

The validation report measures benign false-positive rate and attack detection rate. The threshold is the 1st percentile of training-benign Isolation Forest decision scores. Anomaly scores are not probabilities.

### Importing the earlier standalone Agent 2 artifact

The repository currently tracks one legacy teammate-supplied Agent 2 artifact at `models/model.native.joblib`. It is not loaded automatically and is not the versioned runtime artifact expected by the API. If (and only if) you trust its provenance, convert it before placing it at the API's expected path:

```bash
python scripts/import_agent2_artifact.py --source models/model.native.joblib --destination models/anomaly_detection/model.joblib
```

Joblib uses Python pickle serialization and loading it can execute code. Do not import artifacts from unknown sources. The adapter preserves the stored threshold and legacy zero-fill preprocessing. It cannot reconstruct the old training distribution's feature profiles, so feature-level anomaly explanations are unavailable for imported artifacts. Prefer retraining with the native Agent 2 trainer. This legacy artifact does not provide Agent 1; train Agent 1 separately from the authorized labelled training partition. Do not commit additional trained binary artifacts or organizer data.

## Agent 3 — evidence fusion

No model training. This deterministic arbiter combines Agent 1 class/confidence and Agent 2 anomaly flag/score into AGREE, DISAGREE, or INCOMPLETE and simulated ALLOW/BLOCK/REVIEW. Incomplete evidence defaults to REVIEW.

## Agent 4 — temporal correlation

No model training. This stateful rule-based correlator uses a 150-flow sliding window and endpoint evidence to identify port scans, DDoS/DoS patterns, and repeated authentication attempts. Its effectiveness must be validated with chronological replay scenarios; it is not trained with labels.

## Agent 5 — adaptive defense

No model training. This policy lifecycle manager checks previously activated simulated policies, creates temporary forward-looking source-identity policies, and expires them. Validate causality (a flow cannot block itself) and expiry with replay tests. It never modifies the host firewall.

## Full-system verification

After installing both versioned artifacts at the paths above:

```bash
python -m pytest tests -q
python scripts/reproduce_benchmarks.py
```

The benchmark requires the organizer-provided evaluation parquet at `data/processed/eval_prepared.parquet`. Keep the evaluation split untouched; report the documented cross-split repeated-feature overlap when presenting metrics. Never commit organizer datasets or trained binary model artifacts to Git.
