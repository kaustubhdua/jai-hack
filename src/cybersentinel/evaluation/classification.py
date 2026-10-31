"""Comprehensive classification evaluation metrics for Agent 1 (Threat Detection)."""
from __future__ import annotations

from typing import Any
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)

BENCHMARK_CLASSES = ("BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN")


def evaluate_classifier(
    y_true: Any,
    y_pred: Any,
    classes: tuple[str, ...] = BENCHMARK_CLASSES,
    label_column: str = "label",
) -> dict[str, Any]:
    """Calculate thorough classification evaluation metrics on predictions."""
    if isinstance(y_true, pd.DataFrame) and (hasattr(y_pred, "predict") or hasattr(y_pred, "predict_frame")):
        df = y_true
        agent = y_pred
        y_true_list = df[label_column].astype(str).str.strip().tolist()
        if hasattr(agent, "predict_frame"):
            preds = agent.predict_frame(df)
            y_pred_list = [r.predicted_class for r in preds]
        else:
            y_pred_list = [agent.predict(row.to_dict()).predicted_class for _, row in df.iterrows()]
    else:
        y_true_list = [str(y).strip() for y in y_true]
        y_pred_list = [str(y).strip() for y in y_pred]
    total_samples = len(y_true_list)
    if total_samples == 0:
        raise ValueError("Cannot evaluate empty predictions.")

    class_list = list(classes)

    # 1. Macro and Weighted metrics
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(
        y_true_list, y_pred_list, labels=class_list, average="macro", zero_division=0
    )
    p_weighted, r_weighted, f1_weighted, _ = precision_recall_fscore_support(
        y_true_list, y_pred_list, labels=class_list, average="weighted", zero_division=0
    )

    acc = float(accuracy_score(y_true_list, y_pred_list))
    bal_acc = float(balanced_accuracy_score(y_true_list, y_pred_list))

    # 2. Per-class metrics
    p_per, r_per, f1_per, sup_per = precision_recall_fscore_support(
        y_true_list, y_pred_list, labels=class_list, zero_division=0
    )
    per_class = {}
    for i, cls_name in enumerate(class_list):
        per_class[cls_name] = {
            "precision": float(round(p_per[i], 6)),
            "recall": float(round(r_per[i], 6)),
            "f1": float(round(f1_per[i], 6)),
            "support": int(sup_per[i]),
        }

    # 3. Confusion Matrix
    cm = confusion_matrix(y_true_list, y_pred_list, labels=class_list)

    # 4. Benign FPR and Attack Detection Rate
    # BENIGN is negative, all attack classes are positive
    y_true_attack = np.array([y != "BENIGN" for y in y_true_list], dtype=bool)
    y_pred_attack = np.array([y != "BENIGN" for y in y_pred_list], dtype=bool)

    # Benign False Positive Rate: false alarms / total benign
    benign_total = int((~y_true_attack).sum())
    benign_false_positives = int(((~y_true_attack) & y_pred_attack).sum())
    benign_fpr = float(benign_false_positives / benign_total) if benign_total > 0 else 0.0

    # Attack Detection Rate: attacks detected as ANY attack / total attacks
    attack_total = int(y_true_attack.sum())
    attacks_detected = int((y_true_attack & y_pred_attack).sum())
    attack_detection_rate = float(attacks_detected / attack_total) if attack_total > 0 else 0.0

    res = {
        "total_samples": total_samples,
        "classes": class_list,
        "accuracy": float(round(acc, 6)),
        "balanced_accuracy": float(round(bal_acc, 6)),
        "macro_precision": float(round(p_macro, 6)),
        "macro_recall": float(round(r_macro, 6)),
        "macro_f1": float(round(f1_macro, 6)),
        "weighted_precision": float(round(p_weighted, 6)),
        "weighted_recall": float(round(r_weighted, 6)),
        "weighted_f1": float(round(f1_weighted, 6)),
        "benign_fpr": float(round(benign_fpr, 6)),
        "benign_false_positive_rate": float(round(benign_fpr, 6)),
        "benign_false_positives": benign_false_positives,
        "benign_total": benign_total,
        "attack_detection_rate": float(round(attack_detection_rate, 6)),
        "attacks_detected": attacks_detected,
        "attack_total": attack_total,
        "per_class": per_class,
        "confusion_matrix": cm.tolist(),
    }
    res["metrics"] = res
    return res
