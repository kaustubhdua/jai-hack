"""Train Agent 1 with optional, explicitly separated validation calibration."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import pandas as pd
from .model import BENCHMARK_CLASSES, ThreatDetectionModel
from .metrics import evaluate_predictions

def _load_frame(path):
    return pd.read_parquet(path) if str(path).lower().endswith((".parquet", ".pq")) else pd.read_csv(path, low_memory=False)

def load_label_mapping(path, observed_labels):
    """Accept only canonical labels or an explicit organiser-supplied mapping."""
    if path is None:
        observed = set(observed_labels)
        if not observed.issubset(set(BENCHMARK_CLASSES)):
            raise ValueError("Original dataset labels found. Supply the exact organiser mapping via --label-map; no mappings are guessed.")
        return {label: label for label in observed}
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    mapping = payload.get("mapping", payload) if isinstance(payload, dict) else None
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError("Label mapping JSON must be a non-empty object.")
    mapping = {str(k): str(v) for k, v in mapping.items()}
    invalid = sorted(set(mapping.values()) - set(BENCHMARK_CLASSES))
    if invalid:
        raise ValueError(f"Mapping targets must be one of {BENCHMARK_CLASSES}; got {invalid}")
    unknown = sorted(set(observed_labels) - set(mapping))
    if unknown:
        raise ValueError(f"Unmapped dataset labels found: {unknown}")
    return mapping

def _mapped_labels(frame, column, mapping, split_name):
    if column not in frame.columns:
        raise ValueError(f"{split_name} label column {column!r} not found.")
    raw = frame[column].astype("string").str.strip()
    if raw.isna().any() or (raw == "").any():
        raise ValueError(f"{split_name} labels contain missing or empty values.")
    unknown = sorted(set(raw.unique()) - set(mapping))
    if unknown:
        raise ValueError(f"Unmapped {split_name} labels: {unknown}")
    return raw.map(mapping).astype(str)

def train_from_csv(train_csv, label_column, model_out="models/threat_detection/model.joblib",
                   label_map=None, validation_csv=None, validation_label_column=None,
                   backend="random_forest", n_estimators=400, random_state=42,
                   report_out="reports/generated/threat_detection_training.json",
                   calibration_validation_csv=None, calibration_label_column=None):
    frame = _load_frame(train_csv)
    if label_column not in frame.columns:
        raise ValueError(f"Training label column {label_column!r} not found.")
    raw_training_labels = frame[label_column].astype("string").str.strip()
    if raw_training_labels.isna().any() or (raw_training_labels == "").any():
        raise ValueError("Training labels contain missing or empty values.")
    mapping = load_label_mapping(label_map, raw_training_labels.unique().tolist())
    labels = _mapped_labels(frame, label_column, mapping, "Training")
    model = ThreatDetectionModel(backend=backend, n_estimators=n_estimators,
                                 random_state=random_state).fit(frame.drop(columns=[label_column]), labels)
    result = {
        "model_path": str(model_out), "backend": backend, "training_rows": len(frame),
        "feature_count": len(model.feature_columns), "class_counts": model.metadata["class_counts"],
        "classes": list(BENCHMARK_CLASSES), "confidence_calibration": None, "validation": None,
    }
    if calibration_validation_csv:
        if Path(calibration_validation_csv).resolve() == Path(train_csv).resolve():
            raise ValueError("Calibration data must be a separate held-out file, not the training file.")
        calibration = _load_frame(calibration_validation_csv)
        calibration_column = calibration_label_column or label_column
        calibration_labels = _mapped_labels(calibration, calibration_column, mapping, "Calibration")
        calibration_metrics = model.calibrate_confidence(
            calibration.drop(columns=[calibration_column]), calibration_labels
        )
        result["confidence_calibration"] = {
            **calibration_metrics, "source": str(calibration_validation_csv),
            "method": "scalar temperature scaling on held-out labelled validation data",
        }
    if validation_csv:
        if Path(validation_csv).resolve() == Path(train_csv).resolve():
            raise ValueError("Validation data must be separate from the training file.")
        valid = _load_frame(validation_csv)
        target = validation_label_column or label_column
        truth = _mapped_labels(valid, target, mapping, "Validation")
        predicted = [p["predicted_class"] for p in model.predict_frame(valid.drop(columns=[target]))]
        result["validation"] = {
            **evaluate_predictions(truth.tolist(), predicted), "source": str(validation_csv),
            "confidence_calibrated": bool(model.metadata.get("confidence_calibrated")),
        }
    # Persist only after optional calibration so the artifact matches the report.
    model.save(model_out)
    result["artifact_metadata"] = model.metadata
    if report_out:
        destination = Path(report_out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result

def main():
    parser = argparse.ArgumentParser(description="Train CyberSentinel Agent 1.")
    parser.add_argument("--train", "--train-csv", dest="train_csv", required=True)
    parser.add_argument("--label-column", required=True)
    parser.add_argument("--model-out", default="models/threat_detection/model.joblib")
    parser.add_argument("--label-map")
    parser.add_argument("--validation", "--validation-csv", dest="validation_csv")
    parser.add_argument("--validation-label-column")
    parser.add_argument("--calibration-validation", help="Separate labelled validation CSV or Parquet used only for confidence calibration")
    parser.add_argument("--calibration-label-column")
    parser.add_argument("--backend", choices=["random_forest", "xgboost"], default="random_forest")
    parser.add_argument("--n-estimators", type=int, default=400)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--report-out", default="reports/generated/threat_detection_training.json")
    args = parser.parse_args()
    result = train_from_csv(
        args.train_csv, args.label_column, args.model_out, args.label_map,
        args.validation_csv, args.validation_label_column, args.backend,
        args.n_estimators, args.random_state, args.report_out,
        args.calibration_validation, args.calibration_label_column,
    )
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
