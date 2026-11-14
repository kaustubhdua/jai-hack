"""Evaluate both agents on an untouched labelled evaluation file.

All model fitting and anomaly threshold selection must happen before this
command, using training data only. This script only loads artifacts and scores.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support

from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent
from cybersentinel.agents.fusion import EvidenceFusionAgent
from cybersentinel.agents.threat_detection import ThreatDetectionAgent
from cybersentinel.contracts import BenchmarkClass


CLASSES = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]


def load_frame(path: str) -> pd.DataFrame:
    return pd.read_parquet(path) if path.lower().endswith((".parquet", ".pq")) else pd.read_csv(path, low_memory=False)


def evaluate(eval_path: str, threat_path: str, anomaly_path: str, output: str, fusion_sample: int = 5000) -> dict:
    frame = load_frame(eval_path)
    if "label" not in frame.columns:
        raise ValueError("Evaluation file must contain the canonical label column.")
    if frame.empty:
        raise ValueError("Evaluation file contains no rows.")
    raw_truth = frame["label"]
    if raw_truth.isna().any():
        raise ValueError("Evaluation labels contain missing values.")
    truth = raw_truth.astype(str).str.strip()
    if (truth == "").any():
        raise ValueError("Evaluation labels contain empty values.")
    unknown = sorted(set(truth.unique()) - set(CLASSES))
    if unknown:
        raise ValueError(f"Evaluation labels are not canonical benchmark classes: {unknown}")
    features = frame.drop(columns=["label"], errors="ignore")

    threat = ThreatDetectionAgent.load(threat_path)
    anomaly = AnomalyDetectionAgent.load(anomaly_path)

    started = time.perf_counter()
    predictions = threat.predict_many(features)
    threat_seconds = time.perf_counter() - started
    y_pred = [item["predicted_class"] for item in predictions]
    y_true = truth.tolist()
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=CLASSES, zero_division=0
    )
    cm = confusion_matrix(y_true, y_pred, labels=CLASSES)

    started = time.perf_counter()
    if hasattr(anomaly, "score_frame"):
        anomaly_results = anomaly.score_frame(features)
    else:
        anomaly_results = [anomaly.score(row) for row in features.to_dict(orient="records")]
    anomaly_seconds = time.perf_counter() - started
    anomaly_flags = np.asarray([bool(item.is_anomaly) for item in anomaly_results])
    benign_mask = np.asarray(y_true) == "BENIGN"
    attack_mask = ~benign_mask
    benign_fpr = float(anomaly_flags[benign_mask].mean()) if benign_mask.any() else None
    attack_recall = float(anomaly_flags[attack_mask].mean()) if attack_mask.any() else None

    fusion = EvidenceFusionAgent()
    rng = np.random.default_rng(42)
    indices = rng.choice(len(frame), size=min(max(0, fusion_sample), len(frame)), replace=False)
    actions = {"ALLOW": 0, "BLOCK": 0, "REVIEW": 0}
    # Keep this mapping aligned with EvidenceFusionAgent's contract:
    # AGREE, CONFLICT, and UNCERTAIN.
    evidence_status = {"AGREE": 0, "CONFLICT": 0, "UNCERTAIN": 0}
    for idx in indices:
        result = fusion.fuse(predictions[int(idx)], anomaly_results[int(idx)])
        actions[result.action] += 1
        evidence_status[result.evidence_status] += 1

    report = {
        "evaluation_dataset": {
            "path": str(eval_path),
            "rows": len(frame),
            "feature_count": len(features.columns),
            "class_counts": {label: int((truth == label).sum()) for label in CLASSES},
            "evaluation_only": True,
        },
        "agent_1_threat_detection": {
            "model_type": threat.model.backend,
            "training_rows": threat.model.metadata.get("training_rows"),
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "macro_precision": float(np.mean(precision)),
            "macro_recall": float(np.mean(recall)),
            "macro_f1": float(np.mean(f1)),
            "per_class": {
                label: {"precision": float(precision[i]), "recall": float(recall[i]),
                        "f1": float(f1[i]), "support": int(support[i])}
                for i, label in enumerate(CLASSES)
            },
            "confusion_matrix": cm.tolist(),
            "class_order": CLASSES,
            "inference_seconds": threat_seconds,
            "inference_ms_per_flow": threat_seconds * 1000 / len(frame),
            "confidence_note": "Maximum predict_proba; not probability-calibrated.",
        },
        "agent_2_anomaly_detection": {
            "algorithm": "IsolationForest",
            "training_rows": anomaly.metadata.get("training_rows"),
            "threshold": anomaly.threshold,
            "benign_false_positive_rate": benign_fpr,
            "attack_anomaly_recall": attack_recall,
            "inference_seconds": anomaly_seconds,
            "inference_ms_per_flow": anomaly_seconds * 1000 / len(frame),
        },
        "agent_3_evidence_fusion_sample": {
            "sample_size": len(indices),
            "actions": actions,
            "evidence_status": evidence_status,
            "note": "Decision distribution only; not a standalone classification accuracy metric.",
        },
    }
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eval", required=True, help="Prepared official evaluation CSV or Parquet")
    parser.add_argument("--threat-model", default="models/threat_detection/model.joblib")
    parser.add_argument("--anomaly-model", default="models/anomaly_detection/model.joblib")
    parser.add_argument("--output", default="reports/generated/official_evaluation.json")
    parser.add_argument("--fusion-sample", type=int, default=5000)
    args = parser.parse_args()
    print(json.dumps(evaluate(args.eval, args.threat_model, args.anomaly_model, args.output, args.fusion_sample), indent=2))


if __name__ == "__main__":
    main()
