"""Leave-One-Attack-Out (LOAO) Evaluation Framework.

Tests the ability of the multi-agent system (A1 classifier, A2 anomaly detector,
and A3 evidence fusion) to detect novel, previously unseen attack classes that were
completely absent during supervised classifier training.
"""
from __future__ import annotations

import logging
from typing import Any
import numpy as np
import pandas as pd

from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent
from cybersentinel.agents.fusion import EvidenceFusionAgent
from cybersentinel.agents.threat_detection import ThreatDetectionAgent
from cybersentinel.agents.threat_detection.model import BENCHMARK_CLASSES, ThreatDetectionModel

logger = logging.getLogger("cybersentinel.evaluation.loao")

ATTACK_CLASSES = ("BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN")


def evaluate_single_loao_experiment(
    train_df: pd.DataFrame,
    eval_df: pd.DataFrame,
    held_out_class: str,
    anomaly_agent: AnomalyDetectionAgent,
    a1_n_estimators: int = 100,
    random_state: int = 42,
    benign_eval_sample_size: int = 10000,
) -> dict[str, Any]:
    """Execute one Leave-One-Attack-Out trial where held_out_class is excluded from training."""
    if held_out_class not in ATTACK_CLASSES:
        raise ValueError(f"Held out class must be one of {ATTACK_CLASSES}; got {held_out_class}")

    logger.info("Executing LOAO experiment: holding out %s...", held_out_class)

    # 1. Filter training data: exclude held_out_class completely
    train_subset = train_df[train_df["label"] != held_out_class].copy()
    remaining_classes = sorted(train_subset["label"].unique().tolist())
    logger.info("LOAO training subset classes: %s (%d rows)", remaining_classes, len(train_subset))

    # 2. Train A1 on the 4 remaining classes with canonical probability mapping
    a1_model = ThreatDetectionModel(
        backend="random_forest",
        n_estimators=a1_n_estimators,
        random_state=random_state,
        allow_missing_classes=True,
    )
    feature_cols = [c for c in train_subset.columns if c != "label"]
    a1_model.fit(train_subset[feature_cols], train_subset["label"])
    threat_agent = ThreatDetectionAgent(a1_model)

    fusion_agent = EvidenceFusionAgent()

    # 3. Test on Held-Out Attack Flows
    eval_held_out = eval_df[eval_df["label"] == held_out_class].copy()
    total_held_out = len(eval_held_out)
    if total_held_out == 0:
        raise ValueError(f"No evaluation records found for held-out class {held_out_class}")

    held_out_features = eval_held_out.drop(columns=["label"], errors="ignore")
    a1_heldout_preds = threat_agent.predict_many(held_out_features)

    # A1 behavior on novel attack: What did it predict?
    a1_predictions_dist: dict[str, int] = {}
    a1_malicious_count = 0
    for p in a1_heldout_preds:
        cls_pred = p["predicted_class"]
        a1_predictions_dist[cls_pred] = a1_predictions_dist.get(cls_pred, 0) + 1
        if cls_pred != "BENIGN":
            a1_malicious_count += 1

    a1_malicious_detection_rate = float(round(a1_malicious_count / total_held_out, 6))

    # A2 anomaly detector on novel attack
    if hasattr(anomaly_agent, "score_frame"):
        a2_heldout_results = anomaly_agent.score_frame(held_out_features)
    else:
        a2_heldout_results = [anomaly_agent.score(row) for row in held_out_features.to_dict(orient="records")]

    a2_anomaly_count = sum(1 for r in a2_heldout_results if bool(r.is_anomaly))
    a2_anomaly_detection_rate = float(round(a2_anomaly_count / total_held_out, 6))

    # A3 fusion on novel attack
    fusion_actions = {"ALLOW": 0, "REVIEW": 0, "BLOCK": 0}
    fusion_evidence = {"AGREE": 0, "DISAGREE": 0, "INCOMPLETE": 0}

    for idx in range(total_held_out):
        f_res = fusion_agent.fuse(a1_heldout_preds[idx], a2_heldout_results[idx])
        fusion_actions[f_res.action] = fusion_actions.get(f_res.action, 0) + 1
        fusion_evidence[f_res.evidence_status] = fusion_evidence.get(f_res.evidence_status, 0) + 1

    block_rate = float(round(fusion_actions.get("BLOCK", 0) / total_held_out, 6))
    review_rate = float(round(fusion_actions.get("REVIEW", 0) / total_held_out, 6))
    allow_rate = float(round(fusion_actions.get("ALLOW", 0) / total_held_out, 6))
    block_or_review_rate = float(round((fusion_actions.get("BLOCK", 0) + fusion_actions.get("REVIEW", 0)) / total_held_out, 6))

    # 4. Evaluate on Benign Eval subset (to check false block / review rates)
    eval_benign = eval_df[eval_df["label"] == "BENIGN"].copy()
    if len(eval_benign) > benign_eval_sample_size:
        eval_benign = eval_benign.sample(n=benign_eval_sample_size, random_state=random_state)
    benign_total = len(eval_benign)

    benign_features = eval_benign.drop(columns=["label"], errors="ignore")
    a1_benign_preds = threat_agent.predict_many(benign_features)

    if hasattr(anomaly_agent, "score_frame"):
        a2_benign_results = anomaly_agent.score_frame(benign_features)
    else:
        a2_benign_results = [anomaly_agent.score(row) for row in benign_features.to_dict(orient="records")]

    benign_actions = {"ALLOW": 0, "REVIEW": 0, "BLOCK": 0}
    for idx in range(benign_total):
        b_f_res = fusion_agent.fuse(a1_benign_preds[idx], a2_benign_results[idx])
        benign_actions[b_f_res.action] = benign_actions.get(b_f_res.action, 0) + 1

    benign_false_block_rate = float(round(benign_actions.get("BLOCK", 0) / benign_total, 6))
    benign_false_review_rate = float(round(benign_actions.get("REVIEW", 0) / benign_total, 6))
    benign_allow_rate = float(round(benign_actions.get("ALLOW", 0) / benign_total, 6))

    return {
        "held_out_attack_class": held_out_class,
        "training_classes": remaining_classes,
        "held_out_eval_records": total_held_out,
        "agent_1_classifier_behavior": {
            "predicted_classes_distribution": a1_predictions_dist,
            "flagged_as_malicious_count": a1_malicious_count,
            "flagged_as_malicious_rate": a1_malicious_detection_rate,
            "misclassified_as_benign_rate": float(round(a1_predictions_dist.get("BENIGN", 0) / total_held_out, 6)),
        },
        "agent_2_anomaly_detector_behavior": {
            "flagged_as_anomaly_count": a2_anomaly_count,
            "anomaly_detection_recall": a2_anomaly_detection_rate,
        },
        "agent_3_fusion_decisions": {
            "actions": fusion_actions,
            "evidence_status": fusion_evidence,
            "block_rate": block_rate,
            "review_rate": review_rate,
            "allow_rate": allow_rate,
            "containment_rate_block_or_review": block_or_review_rate,
        },
        "benign_control_evaluation": {
            "benign_evaluated_records": benign_total,
            "benign_actions": benign_actions,
            "benign_allow_rate": benign_allow_rate,
            "benign_false_block_rate": benign_false_block_rate,
            "benign_false_review_rate": benign_false_review_rate,
        },
    }


def run_all_loao_experiments(
    train_df: pd.DataFrame,
    eval_df: pd.DataFrame,
    anomaly_agent: AnomalyDetectionAgent,
    a1_n_estimators: int = 100,
    random_state: int = 42,
    benign_eval_sample_size: int = 10000,
) -> dict[str, Any]:
    """Execute complete 4-trial Leave-One-Attack-Out suite across all attack classes."""
    results: dict[str, Any] = {}
    summary_table = []

    for held_out in ATTACK_CLASSES:
        trial = evaluate_single_loao_experiment(
            train_df=train_df,
            eval_df=eval_df,
            held_out_class=held_out,
            anomaly_agent=anomaly_agent,
            a1_n_estimators=a1_n_estimators,
            random_state=random_state,
            benign_eval_sample_size=benign_eval_sample_size,
        )
        results[held_out] = trial

        summary_table.append({
            "held_out_attack": held_out,
            "records": trial["held_out_eval_records"],
            "a1_malicious_detection_rate": trial["agent_1_classifier_behavior"]["flagged_as_malicious_rate"],
            "a2_anomaly_recall": trial["agent_2_anomaly_detector_behavior"]["anomaly_detection_recall"],
            "a3_block_rate": trial["agent_3_fusion_decisions"]["block_rate"],
            "a3_review_rate": trial["agent_3_fusion_decisions"]["review_rate"],
            "a3_containment_rate": trial["agent_3_fusion_decisions"]["containment_rate_block_or_review"],
            "benign_false_block_rate": trial["benign_control_evaluation"]["benign_false_block_rate"],
        })

    # Overall cross-experiment averages
    avg_a1_detection = float(round(np.mean([row["a1_malicious_detection_rate"] for row in summary_table]), 6))
    avg_a2_recall = float(round(np.mean([row["a2_anomaly_recall"] for row in summary_table]), 6))
    avg_containment = float(round(np.mean([row["a3_containment_rate"] for row in summary_table]), 6))
    avg_benign_block = float(round(np.mean([row["benign_false_block_rate"] for row in summary_table]), 6))

    return {
        "trials": results,
        "summary": summary_table,
        "cross_experiment_averages": {
            "average_a1_unseen_attack_detection_rate": avg_a1_detection,
            "average_a2_unseen_anomaly_recall": avg_a2_recall,
            "average_a3_containment_rate": avg_containment,
            "average_benign_false_block_rate": avg_benign_block,
        },
    }


def evaluate_leave_one_attack_out(
    train_df: pd.DataFrame,
    eval_df: pd.DataFrame,
    anomaly_agent: AnomalyDetectionAgent | None = None,
    a1_n_estimators: int = 100,
    random_state: int = 42,
    benign_eval_sample_size: int = 10000,
    max_train_samples: int | None = None,
) -> dict[str, Any]:
    """Wrapper matching standard evaluation framework interface."""
    if anomaly_agent is None:
        benign_df = train_df[train_df["label"] == "BENIGN"]
        anomaly_agent = AnomalyDetectionAgent().fit(benign_df)

    if max_train_samples is not None:
        if max_train_samples < len(ATTACK_CLASSES) + 1:
            raise ValueError("max_train_samples must leave room for BENIGN and every non-held-out attack class.")
        if len(train_df) > max_train_samples:
            # Stratify the cap so the LOAO fit partition retains every available
            # non-held-out class instead of accidentally dropping a rare class.
            label_counts = train_df["label"].astype(str).value_counts()
            quotas = {
                label: max(1, int(max_train_samples * count / len(train_df)))
                for label, count in label_counts.items()
            }
            while sum(quotas.values()) > max_train_samples:
                candidates = [label for label, quota in quotas.items() if quota > 1]
                if not candidates:
                    raise ValueError("Unable to allocate stratified LOAO training sample.")
                label = max(candidates, key=lambda key: quotas[key] - max_train_samples * label_counts[key] / len(train_df))
                quotas[label] -= 1
            while sum(quotas.values()) < max_train_samples:
                candidates = [label for label, count in label_counts.items() if quotas[label] < count]
                if not candidates:
                    break
                label = max(candidates, key=lambda key: max_train_samples * label_counts[key] / len(train_df) - quotas[key])
                quotas[label] += 1
            sampled = [
                group.sample(n=quotas[label], random_state=random_state)
                for label, group in train_df.groupby("label", sort=True)
            ]
            train_df = pd.concat(sampled).sample(frac=1.0, random_state=random_state).reset_index(drop=True)

    res = run_all_loao_experiments(
        train_df=train_df,
        eval_df=eval_df,
        anomaly_agent=anomaly_agent,
        a1_n_estimators=a1_n_estimators,
        random_state=random_state,
        benign_eval_sample_size=benign_eval_sample_size,
    )
    res["loao_summary"] = {
        "mean_a1_unseen_attack_detection": res["cross_experiment_averages"]["average_a1_unseen_attack_detection_rate"],
        "mean_a2_unseen_anomaly_recall": res["cross_experiment_averages"]["average_a2_unseen_anomaly_recall"],
        "mean_a3_unseen_containment_rate": res["cross_experiment_averages"]["average_a3_containment_rate"],
        "mean_benign_false_block_rate": res["cross_experiment_averages"]["average_benign_false_block_rate"],
    }
    return res

