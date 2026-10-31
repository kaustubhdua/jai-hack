#!/usr/bin/env bash
# One-command local pipeline for the official unlabelled Level 2 replay.
# Requires the organizer archives and the project dependencies installed first.
set -euo pipefail

TRAINING_PACK="${1:-cyber-pack.zip}"
HIDDEN_PACK="${2:-cyber-hidden.zip}"
DATA_DIR="${DATA_DIR:-data}"
MODEL_DIR="${MODEL_DIR:-models}"
REPORT_DIR="${REPORT_DIR:-reports/generated}"
OUTPUT_DIR="${OUTPUT_DIR:-outputs/submission}"

for archive in "$TRAINING_PACK" "$HIDDEN_PACK"; do
  if [[ ! -f "$archive" ]]; then
    echo "Missing organizer archive: $archive" >&2
    exit 2
  fi
done

echo "[1/3] Verify organizer archives and install local datasets"
python scripts/prepare_challenge_data.py \
  --training-pack "$TRAINING_PACK" \
  --hidden-pack "$HIDDEN_PACK" \
  --data-dir "$DATA_DIR"

echo "[2/3] Train A1 and BENIGN-only A2 from the authorized training partition"
python scripts/train_models.py \
  --train "$DATA_DIR/raw/training/flows.parquet" \
  --model-dir "$MODEL_DIR" \
  --report-dir "$REPORT_DIR"

echo "[3/3] Run the complete hidden replay and independently validate all CSVs"
python scripts/generate_submissions.py \
  --input "$DATA_DIR/processed/hidden_replay_input.csv" \
  --threat-model "$MODEL_DIR/threat_detection/model.joblib" \
  --anomaly-model "$MODEL_DIR/anomaly_detection/model.joblib" \
  --output-dir "$OUTPUT_DIR"

echo
echo "Local replay and validation completed."
echo "Official CSVs: $OUTPUT_DIR/classification.csv, $OUTPUT_DIR/replay.csv, $OUTPUT_DIR/policies.csv"
echo "Local summary: $OUTPUT_DIR/summary.json"
echo "Organizer acceptance is not verified by this local workflow."
