"""Classifier vs Evidence Fusion Evaluation (A1 vs A3).

Measures whether multi-agent evidence fusion improves upon standalone supervised
classification, quantifies overrides, corrections, and damages, and separately
evaluates simulated security actions (ALLOW / REVIEW / BLOCK).
"""
from __future__ import annotations

from typing import Any
import numpy as np

from .classification import BENCHMARK_CLASSES, evaluate_classifier


def evaluate_fusion_comparison(
    y_true: list[str],
    a1_predictions: list[str | dict[str, Any]],
    a3_fusion_results: list[Any],
    classes: tuple[str, ...] = BENCHMARK_CLASSES,
) -> dict[str, Any]:
    """Compare A1 classifier against A3 fusion results.

    Separates classification evaluation from security action evaluation.
    Preserves incomplete fusion outputs as explicitly missing.
    """
    total = len(y_true)
    if total == 0:
        raise ValueError("Cannot evaluate empty predictions.")

    # Extract A1 classes
    a1_classes = []
    for p in a1_predictions:
        if isinstance(p, dict):
            a1_classes.append(str(p.get("predicted_class", "")).strip())
        else:
            a1_classes.append(str(p).strip())

    # Extract A3 attributes
    a3_classes = []
    actions = []
    evidence_statuses = []
    incompletes = 0

    for res in a3_fusion_results:
        if isinstance(res, dict):
            fc = res.get("final_class")
            act = res.get("action", "REVIEW")
            ev = res.get("evidence_status", "INCOMPLETE")
        else:
            fc = getattr(res, "final_class", None)
            act = getattr(res, "action", "REVIEW")
            ev = getattr(res, "evidence_status", "INCOMPLETE")

        if ev == "INCOMPLETE" or fc is None:
            incompletes += 1
            a3_classes.append(None)
        else:
            a3_classes.append(str(fc).strip())

        actions.append(str(act).strip().upper())
        evidence_statuses.append(str(ev).strip().upper())

    # 1. Standalone A1 metrics
    a1_metrics = evaluate_classifier(y_true, a1_classes, classes=classes)

    # 2. A3 evaluation on evaluated samples
    valid_indices = [i for i, fc in enumerate(a3_classes) if fc is not None]
    if valid_indices:
        y_true_valid = [y_true[i] for i in valid_indices]
        a3_classes_valid = [a3_classes[i] for i in valid_indices]
        a3_metrics = evaluate_classifier(y_true_valid, a3_classes_valid, classes=classes)
    else:
        a3_metrics = None

    # 3. Override and Impact Analysis
    overridden_indices = []
    corrected_indices = []
    damaged_indices = []
    neutral_overrides = []

    per_class_overrides = {cls_name: {"overridden": 0, "corrected": 0, "damaged": 0} for cls_name in classes}

    for i in range(total):
        target = y_true[i]
        a1_cls = a1_classes[i]
        a3_cls = a3_classes[i]

        if a3_cls is None:
            continue

        if a1_cls != a3_cls:
            overridden_indices.append(i)
            a1_correct = (a1_cls == target)
            a3_correct = (a3_cls == target)

            if not a1_correct and a3_correct:
                corrected_indices.append(i)
                if target in per_class_overrides:
                    per_class_overrides[target]["corrected"] += 1
            elif a1_correct and not a3_correct:
                damaged_indices.append(i)
                if target in per_class_overrides:
                    per_class_overrides[target]["damaged"] += 1
            else:
                neutral_overrides.append(i)

            if target in per_class_overrides:
                per_class_overrides[target]["overridden"] += 1

    total_overrides = len(overridden_indices)
    corrected_count = len(corrected_indices)
    damaged_count = len(damaged_indices)
    net_improvement = corrected_count - damaged_count
    override_accuracy = float(corrected_count / total_overrides) if total_overrides > 0 else 0.0

    # 4. Security Action Evaluation (ALLOW / REVIEW / BLOCK)
    # Never treat security actions as 5-class labels!
    action_counts = {"ALLOW": 0, "REVIEW": 0, "BLOCK": 0}
    action_by_ground_truth: dict[str, dict[str, int]] = {
        cls_name: {"ALLOW": 0, "REVIEW": 0, "BLOCK": 0} for cls_name in classes
    }

    benign_false_blocks = 0
    benign_false_reviews = 0
    attack_false_allows = 0
    attack_blocks = 0
    attack_reviews = 0

    for i in range(total):
        act = actions[i]
        target = y_true[i]
        if act in action_counts:
            action_counts[act] += 1
        if target in action_by_ground_truth and act in action_by_ground_truth[target]:
            action_by_ground_truth[target][act] += 1

        if target == "BENIGN":
            if act == "BLOCK":
                benign_false_blocks += 1
            elif act == "REVIEW":
                benign_false_reviews += 1
        else:
            if act == "ALLOW":
                attack_false_allows += 1
            elif act == "BLOCK":
                attack_blocks += 1
            elif act == "REVIEW":
                attack_reviews += 1

    benign_total = sum(1 for y in y_true if y == "BENIGN")
    attack_total = total - benign_total

    false_block_rate = float(benign_false_blocks / benign_total) if benign_total > 0 else 0.0
    false_review_rate = float(benign_false_reviews / benign_total) if benign_total > 0 else 0.0
    false_allow_rate = float(attack_false_allows / attack_total) if attack_total > 0 else 0.0
    attack_block_rate = float(attack_blocks / attack_total) if attack_total > 0 else 0.0
    attack_containment_rate = float((attack_blocks + attack_reviews) / attack_total) if attack_total > 0 else 0.0

    # 5. Evidence Status Breakdown
    evidence_breakdown = {"AGREE": 0, "DISAGREE": 0, "INCOMPLETE": 0}
    for ev in evidence_statuses:
        if ev in evidence_breakdown:
            evidence_breakdown[ev] += 1

    return {
        "total_evaluated_flows": total,
        "incomplete_or_missing_fusion_count": incompletes,
        "a1_classification_metrics": a1_metrics,
        "a3_fusion_classification_metrics": a3_metrics,
        "override_analysis": {
            "total_predictions_overridden": total_overrides,
            "override_rate": float(round(total_overrides / total, 6)),
            "incorrect_corrected_by_fusion": corrected_count,
            "correct_damaged_by_fusion": damaged_count,
            "neutral_overrides": len(neutral_overrides),
            "net_improvement": net_improvement,
            "fusion_override_accuracy": float(round(override_accuracy, 6)),
            "per_class_overrides": per_class_overrides,
        },
        "security_actions": {
            "total_actions": action_counts,
            "action_by_ground_truth_class": action_by_ground_truth,
            "benign_total": benign_total,
            "benign_false_blocks": benign_false_blocks,
            "benign_false_reviews": benign_false_reviews,
            "benign_false_block_rate": float(round(false_block_rate, 6)),
            "benign_false_review_rate": float(round(false_review_rate, 6)),
            "attack_total": attack_total,
            "attack_false_allows": attack_false_allows,
            "attack_false_allow_rate": float(round(false_allow_rate, 6)),
            "attack_block_rate": float(round(attack_block_rate, 6)),
            "attack_containment_rate": float(round(attack_containment_rate, 6)),
        },
        "evidence_agreement": evidence_breakdown,
    }


def evaluate_classifier_vs_fusion(
    df: Any,
    threat_agent: Any,
    anomaly_agent: Any,
    fusion_agent: Any,
    label_column: str = "label",
) -> dict[str, Any]:
    """End-to-end evaluation comparing A1 predictions against A3 fusion results."""
    import pandas as pd
    if isinstance(df, pd.DataFrame):
        y_true = df[label_column].tolist()
        flows = df.to_dict(orient="records")
    else:
        y_true = [row[label_column] for row in df]
        flows = list(df)

    a1_results = []
    a3_results = []
    for flow in flows:
        a1_res = threat_agent.predict(flow)
        a2_res = anomaly_agent.score(flow)
        a3_res = fusion_agent.fuse(a1_res, a2_res)
        a1_results.append(a1_res)
        a3_results.append(a3_res)

    res = evaluate_fusion_comparison(
        y_true=y_true,
        a1_predictions=a1_results,
        a3_fusion_results=a3_results,
    )
    a1_acc = res["a1_classification_metrics"]["accuracy"]
    a3_acc = res["a3_fusion_classification_metrics"]["accuracy"]
    res["summary"] = {
        "a1_accuracy": a1_acc,
        "a3_accuracy": a3_acc,
        "net_improvement_percentage": (a3_acc - a1_acc) * 100.0,
        "total_overrides": res["override_analysis"]["total_predictions_overridden"],
        "action_distribution": res["security_actions"]["total_actions"],
    }
    res["security_decisions"] = {
        "action_counts": res["security_actions"]["total_actions"],
    }
    return res

