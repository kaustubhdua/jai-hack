# Five-agent training and verification

CyberSentinel has **two learned detection models** and **three deterministic response agents**. Agents 3–5 do not need dataset training.

## Supported training workflow

Prepare the organizer packs and install the project's ML dependencies:

```bash
python scripts/prepare_challenge_data.py \
  --training-pack cyber-pack.zip \
  --hidden-pack cyber-hidden.zip

python -m pip install -e ".[dev,ml]"
```

Train both learned agents from the authorized training partition:

```bash
python scripts/train_models.py \
  --train data/raw/training/flows.parquet
```

By default, the combined trainer makes a deterministic stratified 15% holdout from the training partition. A1 is fitted on the remaining training rows and its confidence is temperature-calibrated on that training-only holdout. A2 is fitted on BENIGN rows from its model-fit subset and derives its default threshold from those benign training scores. The training command does not read the held-out evaluation partition or the hidden replay input.

The saved artifacts are written locally to `models/threat_detection/model.joblib` and `models/anomaly_detection/model.joblib`; generated models are ignored by Git. Do not commit organizer data, fitted artifacts, or generated reports.

## Optional anomaly threshold selection

Use label-based A2 threshold selection only if organizers explicitly permit it and supply a separate labelled validation partition. Pass that file with `--validation` and opt in with `--calibrate-anomaly-threshold`. Do not use the held-out evaluation partition or hidden replay input to select a threshold. The default workflow does not use attack labels to set A2's threshold.

The separate `scripts/train_anomaly.py` entry point supports lower-level A2 training and can calibrate its threshold when a validation file is provided. Treat that option as model selection: use it only with an explicitly permitted, separate labelled validation set, never the official held-out evaluation data.

## Evaluation

Use the evaluation command only after training to measure performance on the untouched labelled evaluation partition:

```bash
python scripts/evaluate_benchmark.py \
  --eval data/raw/evaluation/flows.parquet \
  --threat-model models/threat_detection/model.joblib \
  --anomaly-model models/anomaly_detection/model.joblib \
  --output reports/generated/official_evaluation.json
```

This evaluation step scores existing artifacts; it must not fit models, calibrate confidence, or select thresholds. Report the documented repeated-feature overlap caveat with any result. See [Model Training, Evaluation and Hidden Replay](evaluation.md) for the full data boundary and reproducibility requirements.

## Agent responsibilities

- **Agent 1:** supervised five-class threat classifier.
- **Agent 2:** independent BENIGN-baseline anomaly detector; its exported 0–1 index is higher for more anomalous flows and is not a probability.
- **Agent 3:** deterministic evidence fusion; emits `AGREE`, `CONFLICT`, or `UNCERTAIN`.
- **Agent 4:** chronological, bounded temporal correlation using observed replay fields.
- **Agent 5:** forward-only simulated policy lifecycle. A policy cannot block its own triggering record and never changes a real firewall.

Agents 3–5 are tested through the repository's code tests and chronological replay validation; they are not trained on labels.

## Legacy artifact importer

No trained model binary is shipped in the current repository tree. The optional `scripts/import_agent2_artifact.py` utility is for a separately supplied legacy artifact only. Joblib uses Python pickle serialization, so loading an untrusted file can execute code. Verify its provenance independently, use an isolated trusted environment, and prefer retraining with the supported workflow. Importing an A2 artifact does not provide the A1 model or make the full runtime ready.

## Full-system verification

After preparing authorized data and training both models:

```bash
python -m pytest tests -q
python scripts/generate_submissions.py \
  --input data/processed/hidden_replay_input.csv \
  --output-dir outputs/submission
python scripts/validate_submissions.py \
  --input data/processed/hidden_replay_input.csv \
  --output-dir outputs/submission
```

The hidden replay is unlabelled. Do not calculate or claim hidden-set accuracy, macro-F1, false-block rate, attack recall, or containment from it. A local validator pass is not proof of organizer acceptance; retain the exact input hashes and only claim acceptance after an actual organizer response or receipt.
