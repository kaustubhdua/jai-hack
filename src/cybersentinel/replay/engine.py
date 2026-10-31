"""Replay Engine & Submission Generator for CyberSentinel Level 2.

Replays network flows in chronological order, enforces causal policy evaluation,
and produces the three official competition CSV files:
1. classification.csv
2. policy.csv
3. replay.csv
"""
from __future__ import annotations

import csv
from io import StringIO
import logging
from pathlib import Path
import time
from typing import Any, Callable

import pandas as pd

from cybersentinel.agents.adaptive_defense import AdaptiveDefenseAgent
from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent
from cybersentinel.agents.correlation import TemporalCorrelationAgent
from cybersentinel.agents.fusion import EvidenceFusionAgent
from cybersentinel.agents.threat_detection import ThreatDetectionAgent
from cybersentinel.contracts import AnomalyDetectionResult, ThreatDetectionResult

logger = logging.getLogger("cybersentinel.replay")


def _extract_field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        val = obj.get(name)
    else:
        val = getattr(obj, name, None)
    return val if val is not None else default


class ReplayEngine:
    """Full 5-agent causal replay orchestrator with high-throughput vectorized scoring."""

    def __init__(
        self,
        threat_agent: ThreatDetectionAgent,
        anomaly_agent: AnomalyDetectionAgent,
        fusion_agent: EvidenceFusionAgent | None = None,
        correlation_agent: TemporalCorrelationAgent | None = None,
        defense_agent: AdaptiveDefenseAgent | None = None,
    ):
        self.threat_agent = threat_agent
        self.anomaly_agent = anomaly_agent
        self.fusion_agent = fusion_agent or EvidenceFusionAgent()
        self.correlation_agent = correlation_agent or TemporalCorrelationAgent()
        self.defense_agent = defense_agent or AdaptiveDefenseAgent()

    @classmethod
    def load_default(
        cls,
        threat_path: str | Path = "models/threat_detection/model.joblib",
        anomaly_path: str | Path = "models/anomaly_detection/model.joblib",
    ) -> "ReplayEngine":
        """Load trained models and initialize all 5 agents."""
        threat_file, anomaly_file = Path(threat_path), Path(anomaly_path)
        if not threat_file.is_file() or not anomaly_file.is_file():
            raise FileNotFoundError(f"Model artifacts missing: {threat_file}, {anomaly_file}")
        return cls(
            ThreatDetectionAgent.load(threat_file),
            AnomalyDetectionAgent.load(anomaly_file),
            EvidenceFusionAgent(),
            TemporalCorrelationAgent(),
            AdaptiveDefenseAgent(),
        )

    def run_replay(
        self,
        df: pd.DataFrame,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> dict[str, Any]:
        """Execute causal chronological replay across all records in df."""
        self.correlation_agent.reset()
        self.defense_agent.reset()

        total_rows = len(df)
        has_record_id = "record_id" in df.columns
        record_ids = df["record_id"].tolist() if has_record_id else list(range(total_rows))
        has_label = "label" in df.columns
        labels = df["label"].astype(str).str.strip().str.upper().tolist() if has_label else [""] * total_rows

        start_time = time.perf_counter()

        # 1. Batch / Vectorized Predictions for Agent 1 and Agent 2
        logger.info("Computing predictions for Agent 1 and Agent 2...")
        if hasattr(self.threat_agent, "predict_many"):
            threat_preds = self.threat_agent.predict_many(df)
        else:
            threat_preds = []
            for _, r in df.iterrows():
                res = self.threat_agent.predict(r.to_dict())
                threat_preds.append({
                    "predicted_class": _extract_field(res, "predicted_class", "BENIGN"),
                    "confidence": _extract_field(res, "confidence", 0.99),
                })

        if hasattr(self.anomaly_agent, "score_frame"):
            anomaly_results = self.anomaly_agent.score_frame(df)
            anomaly_scores = [r.anomaly_score if r.anomaly_score is not None else 0.0 for r in anomaly_results]
            is_anomalies = [bool(r.is_anomaly) for r in anomaly_results]
        else:
            anomaly_scores = []
            is_anomalies = []
            for _, r in df.iterrows():
                res = self.anomaly_agent.score(r.to_dict())
                anomaly_scores.append(_extract_field(res, "anomaly_score", 0.0))
                is_anomalies.append(_extract_field(res, "is_anomaly", False))

        # Extract endpoints fast
        dports = df["Destination Port"].fillna(0).astype(int).tolist() if "Destination Port" in df.columns else [0] * total_rows

        src_ip_col = next(
            (column for column in ("source_ip", "Source IP", "src_ip", "src") if column in df.columns),
            None,
        )
        if src_ip_col:
            src_ips = [
                str(value).strip() if pd.notna(value) and str(value).strip() else ""
                for value in df[src_ip_col].tolist()
            ]
        else:
            # Use the same deterministic TCP-stack identity derivation as the
            # standalone correlation API. No port/duration-derived pseudo-hosts.
            src_ips = [
                TemporalCorrelationAgent.derive_source_identity(flow)
                for flow in df.to_dict(orient="records")
            ]

        classification_rows: list[dict[str, Any]] = []
        replay_rows: list[dict[str, Any]] = []

        blocked_count = 0
        allowed_count = 0
        attacks_contained = 0
        benign_preserved = 0
        false_blocks = 0

        # 2. Sequential Causal Policy & Defense Loop
        for step in range(total_rows):
            record_id = record_ids[step]
            src_ip = src_ips[step]
            dport = dports[step]
            ground_truth = labels[step]

            t_pred = threat_preds[step]
            t_class = t_pred.get("predicted_class", "BENIGN")
            t_conf = t_pred.get("confidence", 0.0)
            a_score = float(anomaly_scores[step])
            a_flag = bool(is_anomalies[step])

            threat_obj = ThreatDetectionResult(predicted_class=t_class, confidence=t_conf)
            anomaly_obj = AnomalyDetectionResult(anomaly_score=a_score, is_anomaly=a_flag)
            fusion = self.fusion_agent.fuse(threat_obj, anomaly_obj)

            # Record classification prediction for classification.csv (applies to ALL records)
            classification_rows.append({
                "record_id": record_id,
                "predicted_class": fusion.final_class or t_class or "BENIGN",
                "anomaly score": round(a_score, 5),
                "anomaly_score": round(a_score, 5),
                "evidence status": fusion.evidence_status,
                "evidence_status": fusion.evidence_status,
            })

            # Check pre-filter against active policies
            pre_filter = self.defense_agent.evaluate_pre_filter(
                record_id=record_id,
                source_ip=src_ip,
                current_step=step,
            )

            if pre_filter is not None:
                # Pre-filtered by an active policy
                action = "BLOCK"
                applied_policy_id = pre_filter.applied_policy_id or ""
                blocked_count += 1
                if ground_truth and ground_truth != "BENIGN":
                    attacks_contained += 1
                elif ground_truth == "BENIGN":
                    false_blocks += 1
            else:
                # Flow was not blocked by prior policy -> Permitted for analysis
                allowed_count += 1
                action = "ALLOW"
                applied_policy_id = ""

                if ground_truth == "BENIGN":
                    benign_preserved += 1

                # Correlate flow in temporal sliding window
                flow_summary = {
                    "source_ip": src_ip,
                    "Destination Port": dport,
                }
                correlation = self.correlation_agent.correlate(
                    record_id=record_id,
                    flow=flow_summary,
                    threat_class=t_class,
                    confidence=t_conf,
                )

                # Check if this allowed flow represents an attack requiring a forward policy
                is_attack = (
                    fusion.action == "BLOCK"
                    or (correlation.correlated and correlation.attack_type in ("PORT_SCAN", "DOS", "DDOS", "BRUTE_FORCE"))
                )

                detected_type = correlation.attack_type or t_class or "ATTACK"
                exp_rec_id = record_ids[min(step + self.defense_agent.default_duration, total_rows - 1)]
                self.defense_agent.handle_post_analysis(
                    record_id=record_id,
                    source_ip=src_ip,
                    current_step=step,
                    attack_detected=is_attack,
                    attack_type=detected_type,
                    confidence=t_conf,
                    expires_record_id=exp_rec_id,
                )

            replay_rows.append({
                "record_id": record_id,
                "action": action,
                "applied_policy_id": applied_policy_id,
                "active_policy_id": applied_policy_id,
            })

            if progress_callback and (step % 25000 == 0 or step == total_rows - 1):
                progress_callback(step + 1, total_rows)

        elapsed = time.perf_counter() - start_time
        all_policies = self.defense_agent.all_policies

        policy_rows = [
            {
                "policy_id": p.policy_id,
                "activated_after_record_id": p.activated_after_record_id,
                "scope_type": p.scope_type,
                "scope_value": p.scope_value,
                "expires_after_record_id": p.expires_after_record_id,
                "policy_action": p.policy_action,
            }
            for p in all_policies
        ]

        attack_count = sum(label != "BENIGN" for label in labels) if has_label else None
        benign_count = sum(label == "BENIGN" for label in labels) if has_label else None
        metrics = {
            "total_records": total_rows,
            "blocked_records": blocked_count,
            "allowed_records": allowed_count,
            "policies_created": len(all_policies),
            "attacks_contained": attacks_contained,
            "attacks_allowed": max(0, attack_count - attacks_contained) if attack_count is not None else None,
            "attack_records": attack_count,
            "benign_records": benign_count,
            "benign_preserved": benign_preserved,
            "false_blocks": false_blocks,
            # Keep rates semantically distinct: containment uses all attacks as denominator;
            # block precision uses all BLOCK actions; benign preservation uses all benign flows.
            "containment_rate": round(attacks_contained / max(1, attack_count) * 100, 2) if attack_count is not None else None,
            "block_precision": round(attacks_contained / max(1, blocked_count) * 100, 2) if has_label else None,
            "benign_preservation_rate": round(benign_preserved / max(1, benign_count) * 100, 2) if benign_count is not None else None,
            "false_block_rate": round(false_blocks / max(1, benign_count) * 100, 2) if benign_count is not None else None,
            "elapsed_seconds": round(elapsed, 2),
            "throughput_fps": round(total_rows / max(0.001, elapsed), 1),
        }

        return {
            "classification_rows": classification_rows,
            "policy_rows": policy_rows,
            "replay_rows": replay_rows,
            "metrics": metrics,
        }

    @staticmethod
    def export_csv(rows: list[dict[str, Any]], fieldnames: list[str]) -> str:
        """Serialize rows to CSV string with specified fieldnames."""
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue()

    def generate_submission_files(
        self,
        df: pd.DataFrame,
        output_dir: str | Path = "submissions",
    ) -> dict[str, Path]:
        """Run replay and write the 3 official CSV files to output_dir."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        results = self.run_replay(df)

        # 1. classification.csv
        class_csv = self.export_csv(
            results["classification_rows"],
            ["record_id", "predicted_class", "anomaly score", "evidence status"],
        )
        class_file = out_path / "classification.csv"
        class_file.write_text(class_csv, encoding="utf-8")

        # 2. policy.csv
        policy_csv = self.export_csv(
            results["policy_rows"],
            ["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id", "policy_action"],
        )
        policy_file = out_path / "policy.csv"
        policy_file.write_text(policy_csv, encoding="utf-8")

        # 3. replay.csv
        replay_csv = self.export_csv(
            results["replay_rows"],
            ["record_id", "action", "applied_policy_id"],
        )
        replay_file = out_path / "replay.csv"
        replay_file.write_text(replay_csv, encoding="utf-8")

        logger.info("Generated submission files in %s", out_path)
        return {
            "classification": class_file,
            "policy": policy_file,
            "replay": replay_file,
        }