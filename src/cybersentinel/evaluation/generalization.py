"""Seen vs Unseen Generalization Evaluation.

Determines whether evaluation samples contain exact feature vectors already present
in the training partition, and measures generalization performance separately
on memorized/repeated (seen) vs genuinely novel (unseen) flow patterns.
"""
from __future__ import annotations

import hashlib
from typing import Any
import numpy as np
import pandas as pd

from .classification import BENCHMARK_CLASSES, evaluate_classifier


def canonicalize_feature_vector(row_values: np.ndarray, decimals: int = 4) -> str:
    """Canonicalize a single numeric feature vector into a stable hash string."""
    rounded = np.round(np.nan_to_num(row_values, nan=0.0, posinf=1e9, neginf=-1e9), decimals=decimals)
    signature = ",".join(f"{v:.4f}" for v in rounded)
    return hashlib.sha256(signature.encode("utf-8")).hexdigest()


def build_training_feature_registry(
    train_df: pd.DataFrame,
    feature_columns: list[str],
    decimals: int = 4,
) -> set[str]:
    """Compute unique canonical hashes for all training feature vectors."""
    features = train_df[feature_columns].to_numpy(dtype=np.float64)
    registry = set()
    for row in features:
        registry.add(canonicalize_feature_vector(row, decimals=decimals))
    return registry


def evaluate_feature_generalization(
    train_df: pd.DataFrame,
    eval_df: pd.DataFrame,
    feature_columns: list[str],
    y_eval_pred: list[str],
    classes: tuple[str, ...] = BENCHMARK_CLASSES,
    decimals: int = 4,
) -> dict[str, Any]:
    """Evaluate seen vs unseen sample distribution and performance breakdown."""
    if "label" not in eval_df.columns:
        raise ValueError("eval_df must contain 'label' column.")

    y_eval_true = eval_df["label"].astype(str).str.strip().tolist()
    total_eval = len(eval_df)
    if total_eval == 0:
        raise ValueError("Cannot evaluate empty evaluation dataframe.")

    # 1. Build training feature signature registry
    train_registry = build_training_feature_registry(train_df, feature_columns, decimals=decimals)

    # 2. Check each eval vector against the registry
    eval_matrix = eval_df[feature_columns].to_numpy(dtype=np.float64)
    seen_flags = np.zeros(total_eval, dtype=bool)

    for i in range(total_eval):
        h = canonicalize_feature_vector(eval_matrix[i], decimals=decimals)
        if h in train_registry:
            seen_flags[i] = True

    seen_count = int(seen_flags.sum())
    unseen_count = total_eval - seen_count
    seen_pct = float(round((seen_count / total_eval) * 100, 4))
    unseen_pct = float(round((unseen_count / total_eval) * 100, 4))

    # 3. Class breakdown of seen vs unseen
    class_breakdown = {}
    for cls_name in classes:
        cls_mask = np.array([y == cls_name for y in y_eval_true], dtype=bool)
        cls_total = int(cls_mask.sum())
        cls_seen = int((cls_mask & seen_flags).sum())
        cls_unseen = cls_total - cls_seen
        class_breakdown[cls_name] = {
            "total": cls_total,
            "seen": cls_seen,
            "unseen": cls_unseen,
            "seen_pct": float(round((cls_seen / cls_total) * 100, 4)) if cls_total > 0 else 0.0,
            "unseen_pct": float(round((cls_unseen / cls_total) * 100, 4)) if cls_total > 0 else 0.0,
        }

    # 4. Model performance on Seen samples
    y_eval_pred_arr = np.asarray(y_eval_pred)
    if seen_count > 0:
        seen_true = [y_eval_true[i] for i in range(total_eval) if seen_flags[i]]
        seen_pred = [y_eval_pred[i] for i in range(total_eval) if seen_flags[i]]
        seen_metrics = evaluate_classifier(seen_true, seen_pred, classes=classes)
    else:
        seen_metrics = None

    # 5. Model performance on Unseen samples
    if unseen_count > 0:
        unseen_true = [y_eval_true[i] for i in range(total_eval) if not seen_flags[i]]
        unseen_pred = [y_eval_pred[i] for i in range(total_eval) if not seen_flags[i]]
        unseen_metrics = evaluate_classifier(unseen_true, unseen_pred, classes=classes)
    else:
        unseen_metrics = None

    # Performance drop / generalization gap
    if seen_metrics and unseen_metrics:
        gap_accuracy = float(round(seen_metrics["accuracy"] - unseen_metrics["accuracy"], 6))
        gap_macro_f1 = float(round(seen_metrics["macro_f1"] - unseen_metrics["macro_f1"], 6))
    else:
        gap_accuracy = 0.0
        gap_macro_f1 = 0.0

    return {
        "total_eval_samples": total_eval,
        "unique_training_feature_vectors": len(train_registry),
        "seen_feature_vectors": seen_count,
        "unseen_feature_vectors": unseen_count,
        "seen_percentage": seen_pct,
        "unseen_percentage": unseen_pct,
        "per_class_overlap": class_breakdown,
        "seen_subset_metrics": seen_metrics,
        "unseen_subset_metrics": unseen_metrics,
        "generalization_gap": {
            "accuracy_drop": gap_accuracy,
            "macro_f1_drop": gap_macro_f1,
            "interpretation": (
                "Minimal gap indicates strong generalization to unseen network flows."
                if abs(gap_macro_f1) < 0.05
                else "Noticeable gap indicates reliance on repeated feature signatures."
            ),
        },
    }


def evaluate_seen_unseen_generalization(
    train_df: pd.DataFrame,
    eval_df: pd.DataFrame,
    threat_agent: Any,
    feature_columns: list[str] | None = None,
    classes: tuple[str, ...] = BENCHMARK_CLASSES,
) -> dict[str, Any]:
    """High-level evaluation function comparing model performance on seen vs unseen samples."""
    if feature_columns is None:
        if hasattr(threat_agent, "feature_columns") and threat_agent.feature_columns:
            feature_columns = list(threat_agent.feature_columns)
        elif hasattr(threat_agent, "model") and hasattr(threat_agent.model, "feature_columns"):
            feature_columns = list(threat_agent.model.feature_columns)
        else:
            feature_columns = [c for c in eval_df.columns if c not in {"label", "record_id", "source_ip", "srcip", "dstip", "timestamp"}]

    if hasattr(threat_agent, "predict_frame"):
        preds = [r.predicted_class for r in threat_agent.predict_frame(eval_df)]
    else:
        preds = [threat_agent.predict(row.to_dict()).predicted_class for _, row in eval_df.iterrows()]

    res = evaluate_feature_generalization(
        train_df=train_df,
        eval_df=eval_df,
        feature_columns=feature_columns,
        y_eval_pred=preds,
        classes=classes,
    )
    res["generalization_summary"] = {
        "total_eval_samples": res["total_eval_samples"],
        "seen_samples_count": res["seen_feature_vectors"],
        "unseen_samples_count": res["unseen_feature_vectors"],
        "seen_percentage": res["seen_percentage"],
        "unseen_percentage": res["unseen_percentage"],
    }
    res["seen_evaluation"] = res["seen_subset_metrics"] or {"accuracy": 0.0, "macro_f1": 0.0}
    res["unseen_evaluation"] = res["unseen_subset_metrics"] or {"accuracy": 0.0, "macro_f1": 0.0}
    return res

