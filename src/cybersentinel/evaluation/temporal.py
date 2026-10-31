"""Leakage-safe temporal correlation evaluation for Agent 4.

Predictions from Agent 1 drive correlation. Ground-truth labels are used only
after inference to score correlated flows. Campaign-level precision/recall is
not claimed when the dataset has no campaign identifiers.
"""
from __future__ import annotations

import time
from typing import Any

import numpy as np
import pandas as pd

from cybersentinel.agents.correlation import TemporalCorrelationAgent


def _prediction(agent: Any, row: dict[str, Any]) -> tuple[str | None, float | None]:
    result = agent.predict(row)
    predicted_class = getattr(result, "predicted_class", None)
    confidence = getattr(result, "confidence", None)
    status = getattr(result, "status", "success")
    if status != "success" or not predicted_class:
        return None, None
    try:
        confidence = float(confidence) if confidence is not None else None
    except (TypeError, ValueError):
        confidence = None
    return str(predicted_class).strip().upper(), confidence


def evaluate_temporal_correlation(
    eval_df: pd.DataFrame,
    threat_agent: Any,
    window_size: int = 150,
    test_shuffled_robustness: bool = True,
) -> dict[str, Any]:
    """Evaluate Agent 4 using A1 predictions; labels are never fed into the agent."""
    if "label" not in eval_df.columns:
        raise ValueError("eval_df must contain a ground-truth 'label' column.")
    if eval_df.empty:
        raise ValueError("Cannot evaluate temporal correlation on an empty dataframe.")

    records = eval_df.to_dict(orient="records")
    labels = eval_df["label"].astype(str).str.strip().str.upper().tolist()
    record_ids = eval_df["record_id"].tolist() if "record_id" in eval_df.columns else list(range(len(eval_df)))

    # Sort only when every record has a parseable timestamp. Partial timestamps
    # cannot establish a reliable total order, so preserve source order and say so.
    parsed_times = [TemporalCorrelationAgent._parse_timestamp(row) for row in records]
    if all(value is not None for value in parsed_times):
        order = sorted(range(len(records)), key=lambda idx: (parsed_times[idx], idx))
        ordering_mode = "timestamp_sorted"
    else:
        order = list(range(len(records)))
        ordering_mode = "input_order_timestamps_incomplete"

    inference_records = [{key: value for key, value in row.items() if key != "label"} for row in records]
    predictions = [_prediction(threat_agent, inference_records[idx]) for idx in range(len(records))]
    agent = TemporalCorrelationAgent(window_size=window_size)
    correlated_by_ground_truth: dict[str, int] = {}
    correlated_by_predicted_type: dict[str, int] = {}
    group_ids_by_type: dict[str, set[str]] = {
        "PORT_SCAN": set(), "DDOS": set(), "BRUTE_FORCE": set(), "DOS": set()
    }
    correlated_total = 0
    benign_correlated = 0
    attack_correlated = 0
    prediction_errors = 0
    detection_delays: dict[str, list[int]] = {key: [] for key in group_ids_by_type}
    current_run_type: str | None = None
    run_start = 0
    run_detected = False

    started = time.perf_counter()
    for position, original_idx in enumerate(order):
        row = records[original_idx]
        truth = labels[original_idx]
        predicted_class, confidence = predictions[original_idx]
        if predicted_class is None:
            prediction_errors += 1

        # Crucial: pass only the model prediction, never the ground-truth label.
        result = agent.correlate(
            record_ids[original_idx],
            inference_records[original_idx],
            threat_class=predicted_class,
            confidence=confidence,
        )

        if truth == "BENIGN":
            current_run_type = None
            run_detected = False
        elif truth in detection_delays:
            if current_run_type != truth:
                current_run_type = truth
                run_start = position
                run_detected = False
            if result.correlated and not run_detected:
                detection_delays[truth].append(position - run_start)
                run_detected = True

        if result.correlated:
            correlated_total += 1
            correlated_by_ground_truth[truth] = correlated_by_ground_truth.get(truth, 0) + 1
            attack_correlated += int(truth != "BENIGN")
            benign_correlated += int(truth == "BENIGN")
            attack_type = getattr(result, "attack_type", None)
            if attack_type:
                correlated_by_predicted_type[attack_type] = correlated_by_predicted_type.get(attack_type, 0) + 1
                if attack_type in group_ids_by_type and result.group_id:
                    group_ids_by_type[attack_type].add(str(result.group_id))

    elapsed = time.perf_counter() - started
    benign_total = sum(label == "BENIGN" for label in labels)
    attack_total = len(labels) - benign_total
    flow_precision = attack_correlated / correlated_total if correlated_total else None
    benign_false_correlation_rate = benign_correlated / benign_total if benign_total else None
    all_delays = [value for values in detection_delays.values() for value in values]
    delay_summary = {
        attack_type: {
            "contiguous_label_runs_detected": len(values),
            "mean_delay_flows": float(round(float(np.mean(values)), 2)) if values else None,
            "min_delay_flows": int(min(values)) if values else None,
            "max_delay_flows": int(max(values)) if values else None,
        }
        for attack_type, values in detection_delays.items()
    }

    primary = {
        "evaluation_mode": "chronological_replay_using_agent_1_predictions",
        "ordering_mode": ordering_mode,
        "total_flows_evaluated": len(records),
        "processing_time_seconds": float(round(elapsed, 3)),
        "prediction_errors": prediction_errors,
        "correlated_flows_total": correlated_total,
        "correlation_by_ground_truth": correlated_by_ground_truth,
        "correlation_by_predicted_type": correlated_by_predicted_type,
        "campaigns_by_type": {key: len(value) for key, value in group_ids_by_type.items()},
        "total_campaigns_detected": len({group_id for values in group_ids_by_type.values() for group_id in values}),
        "correlated_flow_precision": float(round(flow_precision, 6)) if flow_precision is not None else None,
        "benign_false_correlation_rate": float(round(benign_false_correlation_rate, 6)) if benign_false_correlation_rate is not None else None,
        "detection_delay_by_contiguous_label_run": delay_summary,
        "mean_detection_delay_flows": float(round(float(np.mean(all_delays)), 2)) if all_delays else None,
        "campaign_metrics_available": False,
        "campaign_metrics_limitation": "The supplied evaluation partition has no independently verified campaign IDs; campaign precision/recall is therefore not reported.",
    }

    shuffled_results = None
    if test_shuffled_robustness:
        rng = np.random.default_rng(42)
        shuffled_indices = rng.permutation(len(records))[: min(20000, len(records))]
        shuffled_agent = TemporalCorrelationAgent(window_size=window_size)
        shuffled_correlated = 0
        for idx in shuffled_indices:
            row = inference_records[int(idx)]
            predicted_class, confidence = predictions[int(idx)]
            shuffled_result = shuffled_agent.correlate(
                record_ids[int(idx)], row, threat_class=predicted_class, confidence=confidence
            )
            shuffled_correlated += int(shuffled_result.correlated)
        shuffled_results = {
            "evaluation_mode": "shuffled_order_robustness",
            "shuffled_sample_flows": len(shuffled_indices),
            "shuffled_correlated_flows": shuffled_correlated,
            "interpretation": "Descriptive order-sensitivity check only; not a separate campaign ground-truth evaluation.",
        }

    return {
        "evaluation_summary": primary,
        "chronological_evaluation": primary,
        "shuffled_robustness": shuffled_results,
    }
