"""Probability Calibration Evaluation for Agent 1.

Evaluates and compares uncalibrated vs calibrated probabilities using
Expected Calibration Error (ECE), Multiclass Brier Score, Log Loss,
and Reliability Diagram bin statistics.
"""
from __future__ import annotations

from typing import Any
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import brier_score_loss, log_loss

from cybersentinel.agents.threat_detection.model import BENCHMARK_CLASSES, ThreatDetectionModel


def calculate_expected_calibration_error(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    n_bins: int = 10,
) -> tuple[float, list[dict[str, Any]]]:
    """Calculate Expected Calibration Error (ECE) and reliability bin statistics."""
    confidences = np.max(probabilities, axis=1)
    predictions = np.argmax(probabilities, axis=1)
    accuracies = (predictions == y_true).astype(float)

    bin_boundaries = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    bins_data = []

    total_samples = len(y_true)

    for i in range(n_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]

        if i == n_bins - 1:
            in_bin = (confidences >= bin_lower) & (confidences <= bin_upper)
        else:
            in_bin = (confidences >= bin_lower) & (confidences < bin_upper)

        bin_size = int(np.sum(in_bin))
        if bin_size > 0:
            avg_confidence = float(np.mean(confidences[in_bin]))
            avg_accuracy = float(np.mean(accuracies[in_bin]))
            bin_weight = bin_size / total_samples
            ece += bin_weight * abs(avg_accuracy - avg_confidence)

            bins_data.append({
                "bin_index": i,
                "bin_lower": float(round(bin_lower, 2)),
                "bin_upper": float(round(bin_upper, 2)),
                "sample_count": bin_size,
                "mean_confidence": float(round(avg_confidence, 6)),
                "observed_accuracy": float(round(avg_accuracy, 6)),
                "calibration_gap": float(round(abs(avg_accuracy - avg_confidence), 6)),
            })
        else:
            bins_data.append({
                "bin_index": i,
                "bin_lower": float(round(bin_lower, 2)),
                "bin_upper": float(round(bin_upper, 2)),
                "sample_count": 0,
                "mean_confidence": float(round((bin_lower + bin_upper) / 2, 4)),
                "observed_accuracy": 0.0,
                "calibration_gap": 0.0,
            })

    return float(round(ece, 6)), bins_data


def calculate_multiclass_brier_score(
    y_true_indices: np.ndarray,
    probabilities: np.ndarray,
    n_classes: int,
) -> float:
    """Compute multiclass Brier score (mean squared error of probability vectors)."""
    # One-hot encode targets
    one_hot = np.zeros_like(probabilities)
    for idx, target in enumerate(y_true_indices):
        one_hot[idx, target] = 1.0

    brier = np.mean(np.sum((probabilities - one_hot) ** 2, axis=1))
    return float(round(float(brier), 6))


def evaluate_calibration_pipeline(
    train_df: pd.DataFrame,
    eval_df: pd.DataFrame,
    n_estimators: int = 150,
    calibration_split: float = 0.20,
    random_state: int = 42,
) -> dict[str, Any]:
    """Train on train split, fit calibrators on calibration split, and evaluate on eval set."""
    class_list = list(BENCHMARK_CLASSES)
    class_to_idx = {c: i for i, c in enumerate(class_list)}

    # Stratified split of training data into fit and calibration subsets
    # Shuffle indices
    rng = np.random.default_rng(random_state)
    n_total = len(train_df)
    n_calib = int(n_total * calibration_split)

    indices = rng.permutation(n_total)
    calib_indices = indices[:n_calib]
    fit_indices = indices[n_calib:]

    df_fit = train_df.iloc[fit_indices].copy()
    df_calib = train_df.iloc[calib_indices].copy()

    # 1. Train base model on df_fit
    base_model = ThreatDetectionModel(
        backend="random_forest",
        n_estimators=n_estimators,
        random_state=random_state,
        n_jobs=-1,
    )
    feature_cols = [c for c in train_df.columns if c != "label"]
    base_model.fit(df_fit[feature_cols], df_fit["label"])

    # 2. Fit Isotonic Calibrator using df_calib
    x_calib_features = base_model.imputer.transform(df_calib[base_model.feature_columns])
    y_calib_encoded = base_model.label_encoder.transform(df_calib["label"])

    isotonic_calibrator = CalibratedClassifierCV(
        estimator=FrozenEstimator(base_model.estimator),
        method="isotonic",
    )
    isotonic_calibrator.fit(x_calib_features, y_calib_encoded)

    # 3. Fit Sigmoid / Platt Calibrator using df_calib
    sigmoid_calibrator = CalibratedClassifierCV(
        estimator=FrozenEstimator(base_model.estimator),
        method="sigmoid",
    )
    sigmoid_calibrator.fit(x_calib_features, y_calib_encoded)

    # 4. Evaluate on UNTOUCHED eval_df
    y_eval_true = [str(y).strip() for y in eval_df["label"]]
    y_eval_indices = np.array([class_to_idx[y] for y in y_eval_true], dtype=int)

    # Base uncalibrated probabilities
    raw_uncalibrated_probs = base_model.predict_proba_canonical(eval_df[feature_cols])

    # Calibrated probabilities
    x_eval_features = base_model.imputer.transform(eval_df[base_model.feature_columns])
    iso_raw = isotonic_calibrator.predict_proba(x_eval_features)
    sig_raw = sigmoid_calibrator.predict_proba(x_eval_features)

    # Map calibrated probabilities to canonical 5-class order
    trained_classes = [str(c) for c in base_model.label_encoder.classes_]
    iso_canonical = np.zeros((len(eval_df), len(class_list)), dtype=np.float64)
    sig_canonical = np.zeros((len(eval_df), len(class_list)), dtype=np.float64)

    for i, c in enumerate(class_list):
        if c in trained_classes:
            idx = trained_classes.index(c)
            iso_canonical[:, i] = iso_raw[:, idx]
            sig_canonical[:, i] = sig_raw[:, idx]

    # Metrics for Uncalibrated
    uncal_ece, uncal_bins = calculate_expected_calibration_error(y_eval_indices, raw_uncalibrated_probs)
    uncal_brier = calculate_multiclass_brier_score(y_eval_indices, raw_uncalibrated_probs, len(class_list))
    uncal_logloss = float(round(log_loss(y_eval_indices, np.clip(raw_uncalibrated_probs, 1e-15, 1.0)), 6))

    # Metrics for Isotonic Calibrated
    iso_ece, iso_bins = calculate_expected_calibration_error(y_eval_indices, iso_canonical)
    iso_brier = calculate_multiclass_brier_score(y_eval_indices, iso_canonical, len(class_list))
    iso_logloss = float(round(log_loss(y_eval_indices, np.clip(iso_canonical, 1e-15, 1.0)), 6))

    # Metrics for Sigmoid Calibrated
    sig_ece, sig_bins = calculate_expected_calibration_error(y_eval_indices, sig_canonical)
    sig_brier = calculate_multiclass_brier_score(y_eval_indices, sig_canonical, len(class_list))
    sig_logloss = float(round(log_loss(y_eval_indices, np.clip(sig_canonical, 1e-15, 1.0)), 6))

    # Confidence distribution stats
    uncal_confs = np.max(raw_uncalibrated_probs, axis=1)
    iso_confs = np.max(iso_canonical, axis=1)

    return {
        "evaluation_samples": len(eval_df),
        "calibration_samples": n_calib,
        "training_samples": len(df_fit),
        "uncalibrated": {
            "ece": uncal_ece,
            "brier_score": uncal_brier,
            "log_loss": uncal_logloss,
            "mean_confidence": float(round(float(np.mean(uncal_confs)), 6)),
            "high_confidence_rate_ge_90": float(round(float(np.mean(uncal_confs >= 0.90)), 6)),
            "reliability_diagram_bins": uncal_bins,
        },
        "isotonic_calibrated": {
            "ece": iso_ece,
            "brier_score": iso_brier,
            "log_loss": iso_logloss,
            "mean_confidence": float(round(float(np.mean(iso_confs)), 6)),
            "high_confidence_rate_ge_90": float(round(float(np.mean(iso_confs >= 0.90)), 6)),
            "reliability_diagram_bins": iso_bins,
        },
        "sigmoid_calibrated": {
            "ece": sig_ece,
            "brier_score": sig_brier,
            "log_loss": sig_logloss,
            "reliability_diagram_bins": sig_bins,
        },
        "comparison_summary": {
            "ece_reduction": float(round(uncal_ece - iso_ece, 6)),
            "brier_score_reduction": float(round(uncal_brier - iso_brier, 6)),
            "log_loss_reduction": float(round(uncal_logloss - iso_logloss, 6)),
            "best_calibrator": "isotonic" if iso_ece <= sig_ece else "sigmoid",
        },
    }


def evaluate_probability_calibration(
    train_df: pd.DataFrame,
    eval_df: pd.DataFrame,
    cal_fraction: float = 0.20,
    n_estimators: int = 100,
    random_state: int = 42,
) -> dict[str, Any]:
    """Evaluate probability calibration before and after isotonic/sigmoid scaling."""
    raw = evaluate_calibration_pipeline(
        train_df=train_df,
        eval_df=eval_df,
        n_estimators=n_estimators,
        calibration_split=cal_fraction,
        random_state=random_state,
    )
    best_method = raw["comparison_summary"]["best_calibrator"]
    best_cal = raw[f"{best_method}_calibrated"]

    uncal_bins = raw["uncalibrated"]["reliability_diagram_bins"]
    cal_bins = best_cal["reliability_diagram_bins"]

    evaluation = {
        "method": best_method,
        "ece_reduction": raw["comparison_summary"]["ece_reduction"],
        "brier_reduction": raw["comparison_summary"]["brier_score_reduction"],
        "uncalibrated": {
            "ece": raw["uncalibrated"]["ece"],
            "brier_score": raw["uncalibrated"]["brier_score"],
            "log_loss": raw["uncalibrated"]["log_loss"],
            "reliability_bins": uncal_bins,
        },
        "calibrated": {
            "ece": best_cal["ece"],
            "brier_score": best_cal["brier_score"],
            "log_loss": best_cal["log_loss"],
            "reliability_bins": cal_bins,
        },
    }

    return {
        "summary": raw["comparison_summary"],
        "evaluation": evaluation,
        "uncalibrated": raw["uncalibrated"],
        "isotonic_calibrated": raw["isotonic_calibrated"],
        "sigmoid_calibrated": raw["sigmoid_calibrated"],
    }

