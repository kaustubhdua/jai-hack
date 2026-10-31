"""Independent Anomaly Detection Evaluation for Agent 2 (Isolation Forest).

Calculates ROC-AUC (with inverted decision-function scores so higher indicates anomalous),
Precision-Recall curves, operational threshold performance, per-class anomaly recalls,
and score distribution statistics. Supports 0.5 decision probability mapping.
"""
from __future__ import annotations

from typing import Any
import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_curve,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    roc_curve,
)

BENCHMARK_CLASSES = ("BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN")


def raw_to_anomaly_probability(
    raw_scores: np.ndarray | list[float],
    threshold: float,
    scale: float | None = None,
) -> np.ndarray:
    """Map raw Isolation Forest scores to anomaly probability in [0, 1].

    Decision boundary:
    raw_score <= threshold  ==>  P(anomaly) > 0.5  ==>  Class 1 (Anomaly)
    raw_score > threshold   ==>  P(anomaly) <= 0.5 ==>  Class 0 (Normal)
    """
    scores = np.asarray(raw_scores, dtype=np.float64)
    if scale is None or scale <= 0:
        std = float(np.std(scores))
        scale = max(std, 1e-4)

    # Sigmoid centered at the operational threshold with negative slope:
    # Lower raw score -> positive exponent -> probability closer to 1.0
    logits = -(scores - threshold) / scale
    # Clip for numerical stability
    logits = np.clip(logits, -20.0, 20.0)
    probabilities = 1.0 / (1.0 + np.exp(-logits))
    return probabilities


def evaluate_anomaly_detector(
    y_true: list[str] | np.ndarray | pd.Series,
    raw_scores: list[float] | np.ndarray,
    operational_threshold: float,
    is_anomaly_flags: list[bool] | np.ndarray | None = None,
    classes: tuple[str, ...] = BENCHMARK_CLASSES,
) -> dict[str, Any]:
    """Evaluate Isolation Forest anomaly detector thoroughly."""
    y_true_list = [str(y).strip() for y in y_true]
    scores = np.asarray(raw_scores, dtype=np.float64)
    total_samples = len(y_true_list)
    if total_samples == 0:
        raise ValueError("Cannot evaluate empty predictions.")

    # Ground truth: 1 for any attack class, 0 for BENIGN
    y_binary = np.array([1 if y != "BENIGN" else 0 for y in y_true_list], dtype=int)

    # CRITICAL: Isolation Forest decision_function assigns LOWER scores to more anomalous flows.
    # We must reverse the score when computing ROC and PR curves so higher = more anomalous!
    anomaly_likelihood = -scores

    # 1. ROC-AUC and Curve
    roc_auc = float(roc_auc_score(y_binary, anomaly_likelihood))
    fpr_arr, tpr_arr, roc_thresh = roc_curve(y_binary, anomaly_likelihood)

    # Sample ROC curve points for compact serialization
    roc_sample_indices = np.linspace(0, len(fpr_arr) - 1, min(60, len(fpr_arr)), dtype=int)
    roc_curve_sampled = [
        {"fpr": float(round(fpr_arr[idx], 6)), "tpr": float(round(tpr_arr[idx], 6))}
        for idx in roc_sample_indices
    ]

    # 2. Precision-Recall Curve and Average Precision
    pr_auc = float(average_precision_score(y_binary, anomaly_likelihood))
    prec_arr, rec_arr, _ = precision_recall_curve(y_binary, anomaly_likelihood)

    pr_sample_indices = np.linspace(0, len(prec_arr) - 1, min(60, len(prec_arr)), dtype=int)
    pr_curve_sampled = [
        {"precision": float(round(prec_arr[idx], 6)), "recall": float(round(rec_arr[idx], 6))}
        for idx in pr_sample_indices
    ]

    # 3. Anomaly Probabilities (threshold = 0.5 decision boundary)
    probabilities = raw_to_anomaly_probability(scores, threshold=operational_threshold)
    prob_flags = (probabilities > 0.5).astype(int)

    if is_anomaly_flags is not None:
        operational_flags = np.asarray(is_anomaly_flags, dtype=bool)
    else:
        operational_flags = scores <= operational_threshold

    y_pred_operational = operational_flags.astype(int)

    # 4. Operational Threshold Metrics
    cm = confusion_matrix(y_binary, y_pred_operational)
    tn, fp, fn, tp = cm.ravel()

    benign_fpr = float(fp / (tn + fp)) if (tn + fp) > 0 else 0.0
    attack_recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    operational_precision = float(precision_score(y_binary, y_pred_operational, zero_division=0))
    operational_f1 = float(f1_score(y_binary, y_pred_operational, zero_division=0))

    # 5. Per-Attack-Class Anomaly Recall
    per_class_recalls: dict[str, dict[str, Any]] = {}
    for cls_name in classes:
        cls_mask = np.array([y == cls_name for y in y_true_list], dtype=bool)
        cls_total = int(cls_mask.sum())
        cls_flagged = int(operational_flags[cls_mask].sum())
        recall_rate = float(cls_flagged / cls_total) if cls_total > 0 else 0.0
        cls_scores = scores[cls_mask]

        per_class_recalls[cls_name] = {
            "total_records": cls_total,
            "flagged_as_anomaly": cls_flagged,
            "anomaly_rate": float(round(recall_rate, 6)),
            "score_mean": float(round(float(np.mean(cls_scores)), 6)) if cls_total > 0 else 0.0,
            "score_std": float(round(float(np.std(cls_scores)), 6)) if cls_total > 0 else 0.0,
            "score_median": float(round(float(np.median(cls_scores)), 6)) if cls_total > 0 else 0.0,
            "score_p01": float(round(float(np.percentile(cls_scores, 1)), 6)) if cls_total > 0 else 0.0,
            "score_p99": float(round(float(np.percentile(cls_scores, 99)), 6)) if cls_total > 0 else 0.0,
        }

    # 6. Threshold Sweep Analysis
    sweep_thresholds = np.linspace(np.percentile(scores, 0.5), np.percentile(scores, 30), 20)
    threshold_sweep = []
    for t in sweep_thresholds:
        t_val = float(t)
        t_pred = (scores <= t_val).astype(int)
        t_fpr = float(np.sum((y_binary == 0) & (t_pred == 1)) / max(1, tn + fp))
        t_rec = float(recall_score(y_binary, t_pred, zero_division=0))
        t_prec = float(precision_score(y_binary, t_pred, zero_division=0))
        t_f1 = float(f1_score(y_binary, t_pred, zero_division=0))
        threshold_sweep.append({
            "threshold": float(round(t_val, 6)),
            "benign_fpr": float(round(t_fpr, 6)),
            "attack_recall": float(round(t_rec, 6)),
            "precision": float(round(t_prec, 6)),
            "f1": float(round(t_f1, 6)),
        })

    return {
        "total_samples": total_samples,
        "operational_threshold": float(round(operational_threshold, 6)),
        "probability_decision_boundary": 0.5,
        "roc_auc": float(round(roc_auc, 6)),
        "average_precision_pr_auc": float(round(pr_auc, 6)),
        "operational_metrics": {
            "benign_fpr": float(round(benign_fpr, 6)),
            "attack_recall": float(round(attack_recall, 6)),
            "precision": float(round(operational_precision, 6)),
            "f1_score": float(round(operational_f1, 6)),
            "true_negatives_benign": int(tn),
            "false_positives_benign": int(fp),
            "false_negatives_attacks": int(fn),
            "true_positives_attacks": int(tp),
        },
        "per_class_recalls": per_class_recalls,
        "roc_curve": roc_curve_sampled,
        "pr_curve": pr_curve_sampled,
        "threshold_sweep": threshold_sweep,
    }


def evaluate_anomaly_detection(
    eval_df: pd.DataFrame,
    anomaly_agent: Any,
    threshold: float | None = None,
    label_column: str = "label",
) -> dict[str, Any]:
    """High-level evaluation function for Agent 2 AnomalyDetectionAgent."""
    if label_column not in eval_df.columns:
        raise ValueError(f"Label column '{label_column}' not found in dataframe.")
    y_true = eval_df[label_column].values

    # Run score_frame or score
    if hasattr(anomaly_agent, "score_frame"):
        results = anomaly_agent.score_frame(eval_df)
        raw_scores = [r.anomaly_score if r.anomaly_score is not None else 0.0 for r in results]
        flags = [r.is_anomaly if r.is_anomaly is not None else False for r in results]
    else:
        results = [anomaly_agent.score(row.to_dict()) for _, row in eval_df.iterrows()]
        raw_scores = [r.anomaly_score if r.anomaly_score is not None else 0.0 for r in results]
        flags = [r.is_anomaly if r.is_anomaly is not None else False for r in results]

    op_thresh = threshold if threshold is not None else getattr(anomaly_agent, "threshold", 0.0)
    if op_thresh is None:
        op_thresh = 0.0

    res = evaluate_anomaly_detector(
        y_true=y_true,
        raw_scores=raw_scores,
        operational_threshold=op_thresh,
        is_anomaly_flags=flags,
    )
    res["score_inverted"] = True
    res["average_precision"] = res["average_precision_pr_auc"]
    res["per_attack_class_recall"] = {
        k: v["anomaly_rate"] for k, v in res["per_class_recalls"].items() if k != "BENIGN"
    }
    return res

