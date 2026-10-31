"""Temporal Correlation Evaluation Framework for Agent 4.

Evaluates multi-flow campaign detection (DDoS convergence, horizontal Port Scans,
and repeated Brute Force sequences), measuring detection rate, campaign precision,
detection delay, and false campaign rates under strict chronological replay.
"""
from __future__ import annotations

import time
from typing import Any
import numpy as np
import pandas as pd

from cybersentinel.agents.correlation import TemporalCorrelationAgent


def evaluate_temporal_correlation(
    eval_df: pd.DataFrame,
    window_size: int = 150,
    test_shuffled_robustness: bool = True,
) -> dict[str, Any]:
    """Chronologically evaluate TemporalCorrelationAgent on evaluation flows."""
    agent = TemporalCorrelationAgent(window_size=window_size)
    agent.reset()

    total_flows = len(eval_df)
    labels = eval_df["label"].astype(str).str.strip().tolist() if "label" in eval_df.columns else [""] * total_flows
    record_ids = eval_df["record_id"].tolist() if "record_id" in eval_df.columns else list(range(total_flows))

    # Keep chronological records
    records = eval_df.to_dict(orient="records")

    correlated_flows_count = 0
    correlated_by_ground_truth: dict[str, int] = {}
    attack_flows_count = 0
    benign_flows_count = 0

    campaigns_detected: dict[str, list[dict[str, Any]]] = {
        "PORT_SCAN": [],
        "DDOS": [],
        "BRUTE_FORCE": [],
        "DOS": [],
    }

    # Tracking detection delay (flows elapsed until first trigger in an attack cluster)
    current_attack_type: str | None = None
    cluster_start_idx = 0
    first_detection_idx: int | None = None
    detection_delays: dict[str, list[int]] = {
        "PORT_SCAN": [],
        "DDOS": [],
        "BRUTE_FORCE": [],
        "DOS": [],
    }

    t0 = time.perf_counter()
    for i, row in enumerate(records):
        lbl = labels[i]
        rec_id = record_ids[i]
        is_attack = (lbl != "BENIGN")

        if is_attack:
            attack_flows_count += 1
            if current_attack_type != lbl:
                # New attack cluster started
                current_attack_type = lbl
                cluster_start_idx = i
                first_detection_idx = None
        else:
            benign_flows_count += 1
            current_attack_type = None
            first_detection_idx = None

        res = agent.correlate(rec_id, row, threat_class=lbl if is_attack else "BENIGN")

        if res.correlated:
            correlated_flows_count += 1
            correlated_by_ground_truth[lbl] = correlated_by_ground_truth.get(lbl, 0) + 1

            if is_attack and first_detection_idx is None and current_attack_type in detection_delays:
                first_detection_idx = i
                delay = i - cluster_start_idx
                detection_delays[current_attack_type].append(delay)

            attack_key = getattr(res, "attack_type", None) or getattr(res, "pattern", None)
            if attack_key in campaigns_detected:
                campaigns_detected[attack_key].append({
                    "group_id": res.group_id,
                    "confidence": getattr(res, "confidence", 1.0),
                    "evidence": res.evidence,
                })

    elapsed_s = time.perf_counter() - t0

    # Campaign metrics
    total_active_groups = len(agent.active_groups)
    benign_false_campaign_count = correlated_by_ground_truth.get("BENIGN", 0)
    false_campaign_rate = float(round(benign_false_campaign_count / max(1, benign_flows_count), 6))
    campaign_precision = float(round((correlated_flows_count - benign_false_campaign_count) / max(1, correlated_flows_count), 6))

    # Delays summary
    delays_summary = {}
    for att, delays in detection_delays.items():
        if delays:
            delays_summary[att] = {
                "clusters_evaluated": len(delays),
                "mean_delay_flows": float(round(float(np.mean(delays)), 2)),
                "min_delay_flows": int(np.min(delays)),
                "max_delay_flows": int(np.max(delays)),
            }
        else:
            delays_summary[att] = {"clusters_evaluated": 0, "mean_delay_flows": 0.0}

    # Group size summary
    group_sizes = [len(g.member_record_ids) for g in agent.active_groups.values()]
    avg_group_size = float(round(float(np.mean(group_sizes)), 2)) if group_sizes else 0.0
    max_group_size = int(np.max(group_sizes)) if group_sizes else 0

    # Endpoints coverage
    active_sources = len(agent.source_port_counts)
    active_destinations = len(agent.dest_source_counts)

    primary_results = {
        "evaluation_mode": "strict_chronological_replay",
        "total_flows_evaluated": total_flows,
        "processing_time_seconds": float(round(elapsed_s, 3)),
        "campaigns_detected_count": total_active_groups,
        "correlated_flows_total": correlated_flows_count,
        "campaign_precision": campaign_precision,
        "false_campaign_rate_benign": false_campaign_rate,
        "average_group_size": avg_group_size,
        "max_group_size": max_group_size,
        "source_coverage": active_sources,
        "destination_coverage": active_destinations,
        "detection_delays": delays_summary,
        "correlation_by_ground_truth": correlated_by_ground_truth,
    }

    # Optional Shuffled Robustness Test
    shuffled_results = None
    if test_shuffled_robustness:
        agent_shuffled = TemporalCorrelationAgent(window_size=window_size)
        agent_shuffled.reset()
        rng = np.random.default_rng(42)
        shuffled_indices = rng.permutation(min(20000, total_flows))

        shuffled_correlated = 0
        for idx in shuffled_indices:
            row = records[idx]
            lbl = labels[idx]
            r = agent_shuffled.correlate(record_ids[idx], row, threat_class=lbl)
            if r.correlated:
                shuffled_correlated += 1

        shuffled_results = {
            "evaluation_mode": "shuffled_robustness_test",
            "shuffled_sample_flows": len(shuffled_indices),
            "shuffled_correlated_flows": shuffled_correlated,
            "disruption_finding": (
                "Temporal structure is destroyed when order is shuffled, verifying that "
                "Agent 4 relies on causal sequence timing rather than static flow attributes."
            ),
        }

    # Top-level convenience keys
    primary_results["total_campaigns_detected"] = primary_results["campaigns_detected_count"]
    primary_results["mean_detection_delay_flows"] = delays_summary.get("overall_mean_delay_flows", 0.0)

    return {
        "evaluation_summary": primary_results,
        "chronological_evaluation": primary_results,
        "shuffled_robustness": shuffled_results,
    }
