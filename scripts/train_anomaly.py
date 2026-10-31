"""Train Agent 2 on BENIGN training rows; optionally calibrate on held-out labels."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import pandas as pd
from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent

BENCHMARK_CLASSES = {"BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"}

def load_frame(path: str | Path) -> pd.DataFrame:
    path = Path(path)
    return pd.read_parquet(path) if path.suffix.lower() in {".parquet", ".pq"} else pd.read_csv(path, low_memory=False)

def train_anomaly(train_path: str, model_out: str, report_out: str,
                  validation_path: str | None = None, max_benign_fpr: float = 0.02,
                  label_column: str = "label") -> dict:
    frame = load_frame(train_path)
    if label_column not in frame.columns:
        raise ValueError("Prepared training file must contain the canonical 'label' column.")
    labels = frame[label_column].astype("string").str.strip().str.upper()
    if labels.isna().any() or (labels == "").any():
        raise ValueError("Training labels contain missing or empty values.")
    unexpected = sorted(set(labels.unique()) - BENCHMARK_CLASSES)
    if unexpected:
        raise ValueError(f"Unexpected benchmark labels: {unexpected}")
    benign = frame.loc[labels == "BENIGN"].drop(columns=[label_column], errors="ignore")
    if benign.empty:
        raise ValueError("No BENIGN training rows available for anomaly baseline.")
    agent = AnomalyDetectionAgent().fit(benign)
    calibration = None
    if validation_path:
        if Path(validation_path).resolve() == Path(train_path).resolve():
            raise ValueError("Anomaly threshold calibration requires a separate held-out validation file.")
        valid = load_frame(validation_path)
        if label_column not in valid.columns:
            raise ValueError("Calibration file must contain the canonical 'label' column.")
        valid_labels = valid[label_column].astype("string").str.strip().str.upper()
        if valid_labels.isna().any() or (valid_labels == "").any():
            raise ValueError("Calibration labels contain missing or empty values.")
        unknown = sorted(set(valid_labels.unique()) - BENCHMARK_CLASSES)
        if unknown:
            raise ValueError(f"Unexpected calibration labels: {unknown}")
        calibration = agent.calibrate_threshold(
            valid.drop(columns=[label_column], errors="ignore"), valid_labels,
            max_benign_fpr=max_benign_fpr,
        )
        calibration["source"] = str(validation_path)
        calibration["selection_method"] = "maximum attack recall subject to configured benign FPR ceiling"
    # Persist only after threshold calibration so artifact and report agree.
    agent.save(model_out)
    report = {
        "agent": "anomaly_detection", "model_path": str(model_out),
        "training_scope": "BENIGN rows from training partition only",
        "training_source": str(train_path), "training_rows": len(benign),
        "feature_count": len(agent.feature_columns), "threshold": agent.threshold,
        "threshold_calibration": calibration, "metadata": agent.metadata,
        "note": "Validation labels select the threshold only; scoring/replay receives feature values and no labels.",
    }
    target = Path(report_out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", required=True, help="Prepared training CSV or Parquet file")
    parser.add_argument("--model-out", default="models/anomaly_detection/model.joblib")
    parser.add_argument("--report-out", default="reports/generated/anomaly_training.json")
    parser.add_argument("--validation", help="Separate labelled validation CSV or Parquet for threshold calibration")
    parser.add_argument("--max-benign-fpr", type=float, default=0.02)
    args = parser.parse_args()
    print(json.dumps(train_anomaly(
        args.train, args.model_out, args.report_out,
        validation_path=args.validation, max_benign_fpr=args.max_benign_fpr,
    ), indent=2))

if __name__ == "__main__":
    main()
