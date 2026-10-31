"""Official CSV Submission Exporter and Strict Semantic Validator.

Produces and verifies the three required competition files:
1. classification.csv
2. policy.csv
3. replay.csv
"""
from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("cybersentinel.replay.submission")

BENCHMARK_CLASSES = {"BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"}
EVIDENCE_STATUSES = {"AGREE", "DISAGREE", "INCOMPLETE"}
ACTIONS = {"ALLOW", "BLOCK"}


class SubmissionValidator:
    """Rigorous semantic and schema validator for Day 2 competition submissions."""

    @staticmethod
    def validate_classification(
        file_path: Path,
        expected_records: list[str | int],
    ) -> dict[str, Any]:
        issues: list[str] = []
        if not file_path.is_file():
            return {"valid": False, "errors": [f"File not found: {file_path}"]}

        seen_records = set()
        row_count = 0

        with file_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            valid_headers = [
                ["record_id", "predicted_class", "anomaly score", "evidence status"],
                ["record_id", "predicted_class", "anomaly_score", "evidence_status"],
            ]
            if reader.fieldnames not in valid_headers:
                issues.append(f"Header mismatch. Expected one of {valid_headers}, found {reader.fieldnames}")

            for idx, row in enumerate(reader):
                row_count += 1
                rec_id = row.get("record_id")
                pred = row.get("predicted_class")
                score_str = row.get("anomaly score") if "anomaly score" in row else row.get("anomaly_score")
                ev_status = row.get("evidence status") if "evidence status" in row else row.get("evidence_status")

                if rec_id in seen_records:
                    issues.append(f"Row {idx}: Duplicate record_id '{rec_id}'")
                seen_records.add(rec_id)

                if pred not in BENCHMARK_CLASSES:
                    issues.append(f"Row {idx}: Invalid predicted_class '{pred}'")

                try:
                    score = float(score_str)
                    if not (-1.0 <= score <= 1.0):
                        issues.append(f"Row {idx}: Anomaly score out of range: {score}")
                except (ValueError, TypeError):
                    issues.append(f"Row {idx}: Non-numeric anomaly score '{score_str}'")

                if ev_status not in EVIDENCE_STATUSES:
                    issues.append(f"Row {idx}: Invalid evidence status '{ev_status}'")

        if len(expected_records) != row_count:
            issues.append(f"Row count mismatch: expected {len(expected_records)}, got {row_count}")

        # Exact ID set validation
        expected_set = {str(r) for r in expected_records}
        seen_set = {str(r) for r in seen_records}
        if seen_set != expected_set:
            missing = list(expected_set - seen_set)[:5]
            unexpected = list(seen_set - expected_set)[:5]
            if missing:
                issues.append(f"Missing expected record IDs (sample): {missing}")
            if unexpected:
                issues.append(f"Unexpected record IDs (sample): {unexpected}")

        return {
            "file": file_path.name,
            "valid": len(issues) == 0,
            "row_count": row_count,
            "errors": issues[:15],
            "total_errors": len(issues),
        }

    @staticmethod
    def validate_policy(file_path: Path) -> dict[str, Any]:
        issues: list[str] = []
        if not file_path.is_file():
            return {"valid": False, "errors": [f"File not found: {file_path}"]}

        policies: dict[str, dict[str, Any]] = {}
        row_count = 0

        with file_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            valid_headers = [
                ["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id", "policy_action"],
                ["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id"],
            ]
            if reader.fieldnames not in valid_headers:
                issues.append(f"Header mismatch. Expected one of {valid_headers}, found {reader.fieldnames}")

            for idx, row in enumerate(reader):
                row_count += 1
                pol_id = row.get("policy_id")
                scope_type = row.get("scope_type")
                action = row.get("policy_action")

                if pol_id in policies:
                    issues.append(f"Row {idx}: Duplicate policy_id '{pol_id}'")
                policies[pol_id] = row

                if scope_type != "SOURCE_IP":
                    issues.append(f"Row {idx}: Scope type must be SOURCE_IP, got '{scope_type}'")

                if action is not None and action != "BLOCK":
                    issues.append(f"Row {idx}: Policy action must be BLOCK, got '{action}'")

        return {
            "file": file_path.name,
            "valid": len(issues) == 0,
            "policy_count": row_count,
            "policies": policies,
            "errors": issues[:15],
            "total_errors": len(issues),
        }

    @staticmethod
    def validate_replay(
        file_path: Path,
        expected_records: list[str | int],
        valid_policies: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        issues: list[str] = []
        if not file_path.is_file():
            return {"valid": False, "errors": [f"File not found: {file_path}"]}

        row_count = 0
        seen_records = set()
        allow_count = 0
        block_count = 0

        with file_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            valid_headers = [
                ["record_id", "action", "applied_policy_id"],
                ["record_id", "action", "active_policy_id"],
            ]
            if reader.fieldnames not in valid_headers:
                issues.append(f"Header mismatch. Expected one of {valid_headers}, found {reader.fieldnames}")

            for idx, row in enumerate(reader):
                row_count += 1
                rec_id = row.get("record_id")
                action = row.get("action")
                applied_pol = (row.get("applied_policy_id") or row.get("active_policy_id") or "").strip()

                if rec_id in seen_records:
                    issues.append(f"Row {idx}: Duplicate record_id '{rec_id}'")
                seen_records.add(rec_id)

                if action not in ACTIONS:
                    issues.append(f"Row {idx}: Invalid action '{action}'")

                if action == "ALLOW":
                    allow_count += 1
                    if applied_pol != "":
                        issues.append(f"Row {idx}: ALLOW action must have empty applied_policy_id, got '{applied_pol}'")
                elif action == "BLOCK":
                    block_count += 1
                    if not applied_pol:
                        issues.append(f"Row {idx}: BLOCK action must reference a valid policy ID")
                    elif applied_pol not in valid_policies:
                        issues.append(f"Row {idx}: BLOCK references unknown policy '{applied_pol}'")

        if len(expected_records) != row_count:
            issues.append(f"Row count mismatch: expected {len(expected_records)}, got {row_count}")

        # Exact ID set validation
        expected_set = {str(r) for r in expected_records}
        seen_set = {str(r) for r in seen_records}
        if seen_set != expected_set:
            missing = list(expected_set - seen_set)[:5]
            unexpected = list(seen_set - expected_set)[:5]
            if missing:
                issues.append(f"Missing expected record IDs (sample): {missing}")
            if unexpected:
                issues.append(f"Unexpected record IDs (sample): {unexpected}")

        return {
            "file": file_path.name,
            "valid": len(issues) == 0,
            "row_count": row_count,
            "allow_count": allow_count,
            "block_count": block_count,
            "errors": issues[:15],
            "total_errors": len(issues),
        }

    @classmethod
    def validate_submission_bundle(
        cls,
        output_dir: Path,
        expected_records: list[str | int],
    ) -> dict[str, Any]:
        """Validate all three files together with cross-file referential integrity."""
        class_res = cls.validate_classification(output_dir / "classification.csv", expected_records)
        policy_res = cls.validate_policy(output_dir / "policy.csv")
        replay_res = cls.validate_replay(output_dir / "replay.csv", expected_records, policy_res.get("policies", {}))

        all_valid = class_res["valid"] and policy_res["valid"] and replay_res["valid"]
        report = {
            "all_valid": all_valid,
            "status": "READY_FOR_SUBMISSION" if all_valid else "VALIDATION_FAILED",
            "classification": class_res,
            "policy": policy_res,
            "replay": replay_res,
        }
        report_file = output_dir / "validation_report.json"
        report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report
