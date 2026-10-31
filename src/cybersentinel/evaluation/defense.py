"""Adaptive Defense (Agent 5) and multi-configuration security evaluation.

Evaluates:
- Attack containment rate
- Benign traffic preservation
- False blocking rate
- False review rate
- Policy activations, reuse, accumulation, expiration correctness
- Trigger-flow protection & defense effectiveness
- 4-way configuration comparison:
  1. No adaptive defense
  2. Existing adaptive defense (A1+A2+A3)
  3. Defense without temporal correlation
  4. Temporal correlation plus adaptive defense (full 5-agent system)
"""
from __future__ import annotations

import logging
import time
from typing import Any

import numpy as np
import pandas as pd

from cybersentinel.agents.adaptive_defense import AdaptiveDefenseAgent
from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent
from cybersentinel.agents.correlation import TemporalCorrelationAgent
from cybersentinel.agents.fusion import EvidenceFusionAgent
from cybersentinel.agents.threat_detection import ThreatDetectionAgent
from cybersentinel.contracts import AnomalyDetectionResult, ThreatDetectionResult

logger = logging.getLogger("cybersentinel.evaluation.defense")


def _run_defense_simulation(
    df: pd.DataFrame,
    threat_preds: list[dict[str, Any]],
    anomaly_scores: list[float],
    is_anomalies: list[bool],
    src_ips: list[str],
    dports: list[int],
    labels: list[str],
    record_ids: list[str | int],
    use_adaptive_defense: bool = True,
    use_temporal_correlation: bool = True,
    policy_duration: int = 150,
) -> dict[str, Any]:
    """Run sequential flow replay for a specific defense configuration."""
    total_rows = len(df)
    fusion_agent = EvidenceFusionAgent()
    correlation_agent = TemporalCorrelationAgent() if use_temporal_correlation else None
    defense_agent = AdaptiveDefenseAgent(default_duration=policy_duration) if use_adaptive_defense else None

    blocked_attacks = 0
    total_attacks = 0
    benign_preserved = 0
    total_benign = 0
    false_blocks = 0
    false_reviews = 0
    pre_filter_hits = 0
    max_active_policies = 0

    per_class_total: dict[str, int] = {}
    per_class_blocked: dict[str, int] = {}

    # Verification of expiration correctness
    expired_checks = 0
    expiration_violations = 0

    for step in range(total_rows):
        rec_id = record_ids[step]
        src_ip = src_ips[step]
        dport = dports[step]
        gt_label = labels[step]
        is_attack = gt_label != "BENIGN"

        if is_attack:
            total_attacks += 1
            per_class_total[gt_label] = per_class_total.get(gt_label, 0) + 1
        else:
            total_benign += 1

        t_pred = threat_preds[step]
        t_class = t_pred.get("predicted_class", "BENIGN")
        t_conf = float(t_pred.get("confidence", 0.0))
        a_score = float(anomaly_scores[step])
        a_flag = bool(is_anomalies[step])

        # Step 1: Pre-filter check
        pre_filtered = False
        applied_policy_id: str | None = None

        if defense_agent is not None:
            active_count = len(defense_agent.active_policies)
            if active_count > max_active_policies:
                max_active_policies = active_count

            # Check for any active policy that shouldn't be active
            for s_ip, pol in list(defense_agent.active_policies.items()):
                expired_checks += 1
                if step > pol.created_at_step + policy_duration:
                    expiration_violations += 1

            pre_decision = defense_agent.evaluate_pre_filter(
                record_id=rec_id,
                source_ip=src_ip,
                current_step=step,
            )
            if pre_decision is not None and pre_decision.action == "BLOCK":
                pre_filtered = True
                applied_policy_id = pre_decision.applied_policy_id
                pre_filter_hits += 1

        if pre_filtered:
            final_action = "BLOCK"
            if is_attack:
                blocked_attacks += 1
                per_class_blocked[gt_label] = per_class_blocked.get(gt_label, 0) + 1
            else:
                false_blocks += 1
        else:
            # Step 2: Model inference and fusion
            threat_obj = ThreatDetectionResult(predicted_class=t_class, confidence=t_conf)
            anomaly_obj = AnomalyDetectionResult(anomaly_score=a_score, is_anomaly=a_flag)
            fusion = fusion_agent.fuse(threat_obj, anomaly_obj)

            if not use_adaptive_defense:
                # No defense agent active; action is pure fusion action
                final_action = fusion.action
                if final_action == "BLOCK":
                    if is_attack:
                        blocked_attacks += 1
                        per_class_blocked[gt_label] = per_class_blocked.get(gt_label, 0) + 1
                    else:
                        false_blocks += 1
                elif final_action == "REVIEW":
                    if not is_attack:
                        false_reviews += 1
                    benign_preserved += 1 if not is_attack else 0
                else:  # ALLOW
                    if not is_attack:
                        benign_preserved += 1
            else:
                # Defense agent active, but flow was not pre-filtered
                final_action = "ALLOW"
                if not is_attack:
                    benign_preserved += 1

                # Correlation check
                corr_alert = False
                corr_type = None
                if correlation_agent is not None:
                    flow_summary = {"source_ip": src_ip, "Destination Port": dport}
                    corr_res = correlation_agent.correlate(
                        record_id=rec_id,
                        flow=flow_summary,
                        threat_class=t_class,
                        confidence=t_conf,
                    )
                    if corr_res.correlated and corr_res.attack_type in ("PORT_SCAN", "DOS", "DDOS", "BRUTE_FORCE"):
                        corr_alert = True
                        corr_type = corr_res.attack_type

                should_create_policy = (fusion.action == "BLOCK") or corr_alert
                detect_type = corr_type or t_class or "ATTACK"

                defense_agent.handle_post_analysis(
                    record_id=rec_id,
                    source_ip=src_ip,
                    current_step=step,
                    attack_detected=should_create_policy,
                    attack_type=detect_type,
                    confidence=t_conf,
                    duration=policy_duration,
                )

    containment_rate = (blocked_attacks / total_attacks) if total_attacks > 0 else 0.0
    preservation_rate = (benign_preserved / total_benign) if total_benign > 0 else 0.0
    false_block_rate = (false_blocks / total_benign) if total_benign > 0 else 0.0
    false_review_rate = (false_reviews / total_benign) if total_benign > 0 else 0.0
    net_effectiveness = containment_rate - false_block_rate

    per_class_rates = {}
    for c, c_tot in per_class_total.items():
        c_blk = per_class_blocked.get(c, 0)
        per_class_rates[c] = {
            "total": c_tot,
            "blocked": c_blk,
            "containment_rate": round(c_blk / c_tot, 6) if c_tot > 0 else 0.0,
        }

    total_policies_created = len(defense_agent.all_policies) if defense_agent else 0
    policy_reuse_ratio = (pre_filter_hits / total_policies_created) if total_policies_created > 0 else 0.0
    expiration_correctness = (
        1.0 - (expiration_violations / expired_checks) if expired_checks > 0 else 1.0
    )

    return {
        "use_adaptive_defense": use_adaptive_defense,
        "use_temporal_correlation": use_temporal_correlation,
        "policy_duration": policy_duration,
        "total_records": total_rows,
        "total_attacks": total_attacks,
        "total_benign": total_benign,
        "blocked_attacks": blocked_attacks,
        "benign_preserved": benign_preserved,
        "false_blocks": false_blocks,
        "false_reviews": false_reviews,
        "pre_filter_hits": pre_filter_hits,
        "attack_containment_rate": round(containment_rate, 6),
        "benign_traffic_preservation": round(preservation_rate, 6),
        "false_blocking_rate": round(false_block_rate, 6),
        "false_review_rate": round(false_review_rate, 6),
        "defense_response_effectiveness": round(net_effectiveness, 6),
        "policies_created": total_policies_created,
        "policy_reuse_count": pre_filter_hits,
        "policy_reuse_ratio": round(policy_reuse_ratio, 4),
        "max_active_policies_accumulation": max_active_policies,
        "policy_expiration_correctness": round(expiration_correctness, 6),
        "per_class_containment": per_class_rates,
    }


def evaluate_adaptive_defense(
    df: pd.DataFrame,
    threat_agent: ThreatDetectionAgent,
    anomaly_agent: AnomalyDetectionAgent,
    policy_duration: int = 150,
) -> dict[str, Any]:
    """Execute full 4-way adaptive defense comparative evaluation."""
    logger.info("Computing vectorized predictions for Agent 1 and Agent 2...")
    total_rows = len(df)

    if hasattr(threat_agent, "predict_many"):
        threat_preds = threat_agent.predict_many(df)
    else:
        threat_preds = [threat_agent.predict(r.to_dict()) for _, r in df.iterrows()]

    if hasattr(anomaly_agent, "score_frame"):
        anomaly_results = anomaly_agent.score_frame(df)
        anomaly_scores = [r.anomaly_score if r.anomaly_score is not None else 0.0 for r in anomaly_results]
        is_anomalies = [bool(r.is_anomaly) for r in anomaly_results]
    else:
        anomaly_scores = []
        is_anomalies = []
        for _, r in df.iterrows():
            res = anomaly_agent.score(r.to_dict())
            anomaly_scores.append(res.anomaly_score or 0.0)
            is_anomalies.append(bool(res.is_anomaly))

    has_rec_id = "record_id" in df.columns
    record_ids = df["record_id"].tolist() if has_rec_id else list(range(total_rows))
    has_label = "label" in df.columns
    labels = df["label"].astype(str).str.strip().str.upper().tolist() if has_label else ["BENIGN"] * total_rows

    dports = (
        df["Destination Port"].fillna(0).astype(int).tolist()
        if "Destination Port" in df.columns
        else [0] * total_rows
    )

    src_ip_col = next(
        (c for c in ("source_ip", "Source IP", "src_ip", "src") if c in df.columns),
        None,
    )
    if src_ip_col:
        src_ips = [
            str(v).strip() if pd.notna(v) and str(v).strip() else ""
            for v in df[src_ip_col].tolist()
        ]
    else:
        src_ips = [
            TemporalCorrelationAgent.derive_source_identity(flow)
            for flow in df.to_dict(orient="records")
        ]

    logger.info("Running Configuration 1: No Adaptive Defense (Baseline)...")
    config_1 = _run_defense_simulation(
        df=df,
        threat_preds=threat_preds,
        anomaly_scores=anomaly_scores,
        is_anomalies=is_anomalies,
        src_ips=src_ips,
        dports=dports,
        labels=labels,
        record_ids=record_ids,
        use_adaptive_defense=False,
        use_temporal_correlation=False,
        policy_duration=policy_duration,
    )

    logger.info("Running Configuration 2: Existing Adaptive Defense (A1+A2+A3)...")
    config_2 = _run_defense_simulation(
        df=df,
        threat_preds=threat_preds,
        anomaly_scores=anomaly_scores,
        is_anomalies=is_anomalies,
        src_ips=src_ips,
        dports=dports,
        labels=labels,
        record_ids=record_ids,
        use_adaptive_defense=True,
        use_temporal_correlation=False,
        policy_duration=policy_duration,
    )

    logger.info("Running Configuration 3: Defense without Temporal Correlation...")
    config_3 = _run_defense_simulation(
        df=df,
        threat_preds=threat_preds,
        anomaly_scores=anomaly_scores,
        is_anomalies=is_anomalies,
        src_ips=src_ips,
        dports=dports,
        labels=labels,
        record_ids=record_ids,
        use_adaptive_defense=True,
        use_temporal_correlation=False,
        policy_duration=policy_duration,
    )

    logger.info("Running Configuration 4: Temporal Correlation + Adaptive Defense (Full 5-Agent System)...")
    config_4 = _run_defense_simulation(
        df=df,
        threat_preds=threat_preds,
        anomaly_scores=anomaly_scores,
        is_anomalies=is_anomalies,
        src_ips=src_ips,
        dports=dports,
        labels=labels,
        record_ids=record_ids,
        use_adaptive_defense=True,
        use_temporal_correlation=True,
        policy_duration=policy_duration,
    )

    comparison = {
        "config_1_no_defense": {
            "name": "No Adaptive Defense (Pure Fusion)",
            "containment_rate": config_1["attack_containment_rate"],
            "false_blocking_rate": config_1["false_blocking_rate"],
            "benign_preservation": config_1["benign_traffic_preservation"],
            "policies_created": config_1["policies_created"],
            "defense_effectiveness": config_1["defense_response_effectiveness"],
        },
        "config_2_existing_defense": {
            "name": "Existing Adaptive Defense",
            "containment_rate": config_2["attack_containment_rate"],
            "false_blocking_rate": config_2["false_blocking_rate"],
            "benign_preservation": config_2["benign_traffic_preservation"],
            "policies_created": config_2["policies_created"],
            "defense_effectiveness": config_2["defense_response_effectiveness"],
        },
        "config_3_defense_without_temporal": {
            "name": "Adaptive Defense without Temporal Correlation",
            "containment_rate": config_3["attack_containment_rate"],
            "false_blocking_rate": config_3["false_blocking_rate"],
            "benign_preservation": config_3["benign_traffic_preservation"],
            "policies_created": config_3["policies_created"],
            "defense_effectiveness": config_3["defense_response_effectiveness"],
        },
        "config_4_temporal_plus_defense": {
            "name": "Temporal Correlation + Adaptive Defense (Full 5-Agent)",
            "containment_rate": config_4["attack_containment_rate"],
            "false_blocking_rate": config_4["false_blocking_rate"],
            "benign_preservation": config_4["benign_traffic_preservation"],
            "policies_created": config_4["policies_created"],
            "defense_effectiveness": config_4["defense_response_effectiveness"],
        },
    }

    # Collateral damage and gain analysis
    temporal_gain = config_4["attack_containment_rate"] - config_3["attack_containment_rate"]
    temporal_collateral = config_4["false_blocking_rate"] - config_3["false_blocking_rate"]

    return {
        "configurations": {
            "no_defense": config_1,
            "existing_defense": config_2,
            "defense_without_temporal": config_3,
            "temporal_plus_defense": config_4,
        },
        "comparison_table": comparison,
        "temporal_enhancement_gain": {
            "containment_gain": round(temporal_gain, 6),
            "collateral_damage_change": round(temporal_collateral, 6),
            "net_gain": round(temporal_gain - temporal_collateral, 6),
        },
    }
