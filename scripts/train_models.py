#!/usr/bin/env python3
"""Train both CyberSentinel production agents from the authorized training partition."""
from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from cybersentinel.agents.threat_detection.model import BENCHMARK_CLASSES, ThreatDetectionModel, numeric_features
from cybersentinel.agents.threat_detection.train import load_label_mapping, train_from_csv
from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent
from scripts.train_anomaly import train_anomaly


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_frame(path: Path) -> pd.DataFrame:
    if path.suffix.lower() in {".parquet", ".pq"}:
        return pd.read_parquet(path)
    return pd.read_csv(path, low_memory=False)


def _write_frame(frame: pd.DataFrame, path: Path) -> None:
    frame.to_parquet(path, index=False)


def train_models(
    training_path: Path,
    model_dir: Path,
    report_dir: Path,
    validation_path: Path | None = None,
    label_column: str = "label",
    label_map: Path | None = None,
    calibration_fraction: float = 0.15,
    random_state: int = 42,
    backend: str = "random_forest",
    n_estimators: int = 400,
    max_benign_fpr: float = 0.02,
    calibrate_anomaly_threshold: bool = False,
) -> dict:
    """Train A1 and benign-only A2, using only training data and a separate calibration split."""
    training_path = Path(training_path)
    model_dir = Path(model_dir)
    report_dir = Path(report_dir)
    if not training_path.is_file():
        raise FileNotFoundError(f"Training partition not found: {training_path}")
    if not 0.0 <= calibration_fraction < 0.5:
        raise ValueError("calibration_fraction must be in [0, 0.5).")
    if calibrate_anomaly_threshold and validation_path is None:
        raise ValueError("Label-based A2 threshold calibration requires a separate organizer-provided --validation file.")
    if validation_path is None and calibration_fraction == 0:
        validation_source = None
    elif validation_path is not None:
        validation_path = Path(validation_path)
        if not validation_path.is_file():
            raise FileNotFoundError(f"Labelled validation partition not found: {validation_path}")
        if training_path.resolve() == validation_path.resolve() or _sha256(training_path) == _sha256(validation_path):
            raise ValueError("Validation must be a separate held-out partition; the training file cannot be reused as validation.")
        validation_source = "organizer_provided_labelled_validation"
    else:
        validation_source = "internal_stratified_holdout_from_training_partition"

    training_frame = _read_frame(training_path)
    if label_column not in training_frame.columns:
        raise ValueError(f"Training label column {label_column!r} is missing.")
    raw_training_labels = training_frame[label_column].astype("string").str.strip()
    if raw_training_labels.isna().any() or (raw_training_labels == "").any():
        raise ValueError("Training labels contain missing or empty values.")
    mapping = load_label_mapping(label_map, raw_training_labels.unique().tolist())
    training_frame[label_column] = raw_training_labels.map(mapping).astype(str)
    if set(training_frame[label_column].unique()) != set(BENCHMARK_CLASSES):
        raise ValueError(f"Training partition must contain all five canonical classes: {sorted(BENCHMARK_CLASSES)}")

    if validation_path is not None:
        validation_frame = _read_frame(validation_path)
        if label_column not in validation_frame.columns:
            raise ValueError(f"Validation label column {label_column!r} is missing.")
        raw_validation_labels = validation_frame[label_column].astype("string").str.strip()
        if raw_validation_labels.isna().any() or (raw_validation_labels == "").any():
            raise ValueError("Validation labels contain missing or empty values.")
        unknown = sorted(set(raw_validation_labels.unique()) - set(mapping))
        if unknown:
            raise ValueError(f"Validation contains labels not present in the training mapping: {unknown}")
        validation_frame[label_column] = raw_validation_labels.map(mapping).astype(str)
        fit_frame = training_frame
        calibration_frame = validation_frame
    elif calibration_fraction > 0:
        # Keep identical numeric feature vectors in one partition to prevent
        # duplicate-row leakage between model fitting and calibration.
        group_features = numeric_features(training_frame.drop(columns=[label_column]))
        groups = pd.util.hash_pandas_object(group_features, index=False).to_numpy()
        group_labels = pd.DataFrame({"group": groups, "label": training_frame[label_column].to_numpy()})
        conflicting = group_labels.groupby("group")["label"].nunique()
        if (conflicting > 1).any():
            raise ValueError("Identical numeric feature rows have conflicting labels; resolve the source data before calibration.")
        groups_per_class = group_labels.drop_duplicates("group").groupby("label")["group"].nunique()
        requested_splits = max(2, round(1.0 / calibration_fraction))
        n_splits = min(requested_splits, int(groups_per_class.min()))
        if n_splits < 2:
            raise ValueError("Not enough distinct feature groups per class for a leakage-safe calibration holdout.")
        splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
        all_classes = set(BENCHMARK_CLASSES)
        selected_split = None
        for fit_indices, calibration_indices in splitter.split(group_features, training_frame[label_column], groups):
            fit_classes = set(training_frame.iloc[fit_indices][label_column])
            calibration_classes = set(training_frame.iloc[calibration_indices][label_column])
            if fit_classes == all_classes and calibration_classes == all_classes:
                selected_split = (fit_indices, calibration_indices)
                break
        if selected_split is None:
            raise ValueError("Could not form a group-isolated calibration holdout containing all five classes; provide a separate labelled validation set or adjust --calibration-fraction.")
        fit_indices, calibration_indices = selected_split
        fit_groups, calibration_groups = set(groups[fit_indices]), set(groups[calibration_indices])
        if fit_groups & calibration_groups:
            raise RuntimeError("Feature-group leakage detected between model-fit and calibration partitions.")
        fit_frame = training_frame.iloc[fit_indices].reset_index(drop=True)
        calibration_frame = training_frame.iloc[calibration_indices].reset_index(drop=True)
    else:
        fit_frame = training_frame
        calibration_frame = None

    if calibration_frame is not None and set(calibration_frame[label_column].unique()) != set(BENCHMARK_CLASSES):
        raise ValueError("Calibration data must contain all five canonical classes for A1 calibration and A2 threshold selection.")

    model_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    a1_path = model_dir / "threat_detection" / "model.joblib"
    a2_path = model_dir / "anomaly_detection" / "model.joblib"
    a1_report = report_dir / "threat_detection_training.json"
    a2_report = report_dir / "anomaly_training.json"

    with tempfile.TemporaryDirectory(prefix="cybersentinel-train-") as temporary:
        temporary_dir = Path(temporary)
        fit_path = temporary_dir / "training_fit.parquet"
        validation_fit_path = temporary_dir / "training_calibration.parquet"
        _write_frame(fit_frame, fit_path)
        fit_data_sha256 = _sha256(fit_path)
        if calibration_frame is not None:
            _write_frame(calibration_frame, validation_fit_path)
            calibration_data_sha256 = _sha256(validation_fit_path)
            validation_arg = validation_fit_path
        else:
            calibration_data_sha256 = None
            validation_arg = None

        threat_report = train_from_csv(
            fit_path,
            label_column=label_column,
            model_out=a1_path,
            label_map=None,
            validation_csv=validation_arg,
            calibration_validation_csv=validation_arg,
            report_out=a1_report,
            backend=backend,
            n_estimators=n_estimators,
        )
        anomaly_report = train_anomaly(
            fit_path,
            model_out=a2_path,
            report_out=a2_report,
            validation_path=validation_arg if calibrate_anomaly_threshold else None,
            label_column=label_column,
            max_benign_fpr=max_benign_fpr,
        )

    # Reload both artifacts so a successful training exit is not mistaken for a loadable model.
    threat = ThreatDetectionModel.load(a1_path)
    anomaly = AnomalyDetectionAgent.load(a2_path)
    if set(threat.label_encoder.classes_) != set(BENCHMARK_CLASSES):
        raise RuntimeError("Reloaded A1 artifact does not contain all five benchmark classes.")
    if int(threat.metadata.get("training_rows") or 0) <= 0:
        raise RuntimeError("Reloaded A1 artifact has no training-row provenance.")
    if int(anomaly.metadata.get("training_rows") or 0) <= 0:
        raise RuntimeError("Reloaded A2 artifact has no benign-training-row provenance.")

    manifest = {
        "training_source": str(training_path),
        "training_sha256": _sha256(training_path),
        "training_rows": int(len(training_frame)),
        "model_training_rows": int(len(fit_frame)),
        "model_fit_data_sha256": fit_data_sha256,
        "calibration_data_sha256": calibration_data_sha256,
        "label_column": label_column,
        "label_mapping": mapping,
        "class_counts_training_partition": training_frame[label_column].value_counts().sort_index().to_dict(),
        "class_counts_model_fit": fit_frame[label_column].value_counts().sort_index().to_dict(),
        "validation_source": validation_source,
        "validation_path": str(validation_path) if validation_path else None,
        "validation_sha256": _sha256(validation_path) if validation_path else None,
        "validation_rows": int(len(calibration_frame)) if calibration_frame is not None else 0,
        "class_counts_validation": calibration_frame[label_column].value_counts().sort_index().to_dict() if calibration_frame is not None else None,
        "calibration_fraction": calibration_fraction if validation_path is None else None,
        "split_random_state": random_state if validation_path is None and calibration_frame is not None else None,
        "a1": {
            "artifact": str(a1_path),
            "artifact_sha256": _sha256(a1_path),
            "training_rows": threat.metadata.get("training_rows"),
            "confidence_calibrated": bool(threat.metadata.get("confidence_calibrated", False)),
        },
        "a2": {
            "artifact": str(a2_path),
            "artifact_sha256": _sha256(a2_path),
            "training_rows": anomaly.metadata.get("training_rows"),
            "threshold_calibrated": anomaly_report.get("threshold_calibration") is not None,
            "threshold_selection_source": "organizer_labelled_validation" if anomaly_report.get("threshold_calibration") is not None else "benign_training_distribution",
            "score_is_probability": False,
            "score_range": [0.0, 1.0],
            "higher_score_means": "more anomalous",
        },
        "reports": {"a1": str(a1_report), "a2": str(a2_report)},
        "evaluation_data_used_for_training_or_calibration": False,
        "hidden_data_used_for_training_or_calibration": False,
        "calibration_metrics_are_tuning_only": calibration_frame is not None,
        "disclosure": "Calibration/threshold-selection metrics are tuning diagnostics, not an unbiased final estimate. The held-out evaluation partition and unlabelled hidden replay input are never used for fitting, calibration, or threshold selection.",
    }
    manifest_path = report_dir / "training_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Train both production CyberSentinel agents.")
    parser.add_argument("--train", type=Path, required=True, help="Organizer training Parquet/CSV.")
    parser.add_argument("--validation", type=Path, default=None, help="Optional separate labelled validation file.")
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--label-map", type=Path, default=None, help="Optional organizer-supplied raw-label mapping JSON.")
    parser.add_argument("--calibration-fraction", type=float, default=0.15, help="Stratified holdout fraction from training when no external validation is supplied; use 0 to disable calibration.")
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--backend", choices=["random_forest", "xgboost"], default="random_forest")
    parser.add_argument("--n-estimators", type=int, default=400)
    parser.add_argument("--max-benign-fpr", type=float, default=0.02)
    parser.add_argument("--calibrate-anomaly-threshold", action="store_true", help="Use labels from a separate organizer-provided --validation file to tune A2 threshold; disabled by default.")
    parser.add_argument("--model-dir", type=Path, default=Path("models"))
    parser.add_argument("--report-dir", type=Path, default=Path("reports/generated"))
    args = parser.parse_args()
    manifest = train_models(
        args.train, args.model_dir, args.report_dir, args.validation,
        args.label_column, args.label_map, args.calibration_fraction,
        args.random_state, args.backend, args.n_estimators, args.max_benign_fpr,
        args.calibrate_anomaly_threshold,
    )
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
