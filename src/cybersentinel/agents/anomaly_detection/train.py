"""Train Agent 2 on BENIGN-only rows and save the repository-native artifact.

Examples:
  python -m cybersentinel.agents.anomaly_detection.train --train data/raw/training/flows.parquet
  python -m cybersentinel.agents.anomaly_detection.train --train train.csv --validation eval.csv
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent


def read_frame(path: str | Path) -> pd.DataFrame:
    path = Path(path)
    if path.suffix.lower() in {".parquet", ".pq"}:
        return pd.read_parquet(path)
    return pd.read_csv(path, low_memory=False)


def train_agent2(train_path: str | Path, model_out: str | Path,
                 report_out: str | Path, validation_path: str | Path | None = None) -> dict:
    frame = read_frame(train_path)
    if "label" not in frame.columns:
        raise ValueError("Training data must contain the canonical 'label' column.")
    labels = frame["label"].astype("string").str.strip().str.upper()
    benign = frame.loc[labels.eq("BENIGN")].drop(columns=["label"])
    if benign.empty:
        raise ValueError("No BENIGN rows found; Agent 2 requires a benign-only baseline.")

    agent = AnomalyDetectionAgent().fit(benign)
    agent.save(model_out)
    report = {
        "agent": "agent_2_anomaly_detection",
        "algorithm": "IsolationForest",
        "training_scope": "BENIGN rows only",
        "training_rows": int(len(benign)),
        "feature_count": len(agent.feature_columns),
        "threshold": float(agent.threshold),
        "threshold_method": agent.metadata["threshold_method"],
        "model_path": str(model_out),
        "validation": None,
    }

    if validation_path:
        valid = read_frame(validation_path)
        if "label" not in valid.columns:
            raise ValueError("Validation data must contain the canonical 'label' column.")
        truth = valid["label"].astype("string").str.strip().str.upper()
        unknown = sorted(set(truth.dropna().unique()) - {"BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"})
        if unknown:
            raise ValueError(f"Unexpected validation labels: {unknown}")
        scored = agent.score_frame(valid.drop(columns=["label"]))
        flags = np.asarray([bool(item.is_anomaly) for item in scored], dtype=bool)
        benign_mask = truth.eq("BENIGN").to_numpy()
        attack_mask = ~benign_mask
        report["validation"] = {
            "rows": int(len(valid)),
            "benign_rows": int(benign_mask.sum()),
            "attack_rows": int(attack_mask.sum()),
            "benign_false_positive_rate": float(flags[benign_mask].mean()) if benign_mask.any() else None,
            "attack_detection_rate": float(flags[attack_mask].mean()) if attack_mask.any() else None,
            "note": "Threshold and model were fitted on training BENIGN rows only; validation labels are used only for metrics.",
        }

    report_path = Path(report_out)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Train CyberSentinel Agent 2.")
    parser.add_argument("--train", required=True, help="Training CSV or Parquet with label column")
    parser.add_argument("--validation", help="Optional held-out validation CSV/Parquet")
    parser.add_argument("--model-out", default="models/anomaly_detection/model.joblib")
    parser.add_argument("--report-out", default="reports/generated/anomaly_detection_training.json")
    args = parser.parse_args()
    print(json.dumps(train_agent2(args.train, args.model_out, args.report_out, args.validation), indent=2))


if __name__ == "__main__":
    main()
