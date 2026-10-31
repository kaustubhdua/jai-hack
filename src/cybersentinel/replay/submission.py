"""Strict validation for the organizer's exact Level 2 submission templates."""
from __future__ import annotations

import csv
import ipaddress
import json
import math
from pathlib import Path
from typing import Any

BENCHMARK_CLASSES = {"BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"}
EVIDENCE_STATUSES = {"AGREE", "CONFLICT", "UNCERTAIN"}
ACTIONS = {"ALLOW", "BLOCK"}
SCOPES = {"SOURCE_IP", "DESTINATION_IP", "SRC_DST_PAIR"}
ALLOW_SENTINEL = "NONE"
CLASS_COLUMNS = ["record_id", "predicted_class", "anomaly_score", "evidence_status"]
POLICY_COLUMNS = [
    "policy_id", "activated_after_record_id", "scope_type",
    "scope_value", "expires_after_record_id",
]
REPLAY_COLUMNS = ["record_id", "action", "active_policy_id"]
SOURCE_KEYS = ("source_ip", "Source IP", "Source_IP", "src_ip", "src")
DESTINATION_KEYS = ("destination_ip", "Destination IP", "Destination_IP", "dst_ip", "dst", "Destination_IP")


def _read_csv(path: Path, expected_columns: list[str]) -> tuple[list[dict[str, str]], list[str]]:
    errors: list[str] = []
    if not path.is_file():
        return [], [f"File not found: {path}"]
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != expected_columns:
            errors.append(f"Header mismatch. Expected {expected_columns}, found {reader.fieldnames}")
        rows = list(reader)
    return rows, errors


def _ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except (ValueError, TypeError):
        return ""


def _endpoint(row: Any, keys: tuple[str, ...]) -> str:
    for key in keys:
        try:
            value = row.get(key)
        except AttributeError:
            value = None
        parsed = _ip(value)
        if parsed:
            return parsed
    return ""


def _scope_for_row(row: Any, scope_type: str) -> str:
    source = _endpoint(row, SOURCE_KEYS)
    destination = _endpoint(row, DESTINATION_KEYS)
    if scope_type == "SOURCE_IP":
        return source
    if scope_type == "DESTINATION_IP":
        return destination
    if scope_type == "SRC_DST_PAIR":
        return f"{source}|{destination}" if source and destination else ""
    return ""


class SubmissionValidator:
    """Validates file structure first, then cross-checks every policy and replay row."""

    @staticmethod
    def validate_classification(file_path: Path, expected_records: list[str | int]) -> dict[str, Any]:
        rows, issues = _read_csv(file_path, CLASS_COLUMNS)
        actual_ids = [str(row.get("record_id", "")) for row in rows]
        expected_ids = [str(value) for value in expected_records]
        if actual_ids != expected_ids:
            issues.append("classification.csv must contain every expected record exactly once in original seq order.")
        for index, row in enumerate(rows):
            if row.get("predicted_class") not in BENCHMARK_CLASSES:
                issues.append(f"Row {index}: invalid predicted_class '{row.get('predicted_class')}'.")
            if row.get("evidence_status") not in EVIDENCE_STATUSES:
                issues.append(f"Row {index}: invalid evidence_status '{row.get('evidence_status')}'.")
            try:
                score = float(row.get("anomaly_score", ""))
                if not math.isfinite(score) or not 0.0 <= score <= 1.0:
                    raise ValueError
            except (TypeError, ValueError):
                issues.append(f"Row {index}: anomaly_score must be finite and within [0,1].")
        return {
            "file": file_path.name, "valid": not issues, "row_count": len(rows),
            "errors": issues[:20], "total_errors": len(issues),
        }

    @staticmethod
    def validate_policy(file_path: Path) -> dict[str, Any]:
        rows, issues = _read_csv(file_path, POLICY_COLUMNS)
        policies: dict[str, dict[str, str]] = {}
        for index, row in enumerate(rows):
            policy_id = str(row.get("policy_id", "")).strip()
            scope_type = str(row.get("scope_type", "")).strip()
            scope_value = str(row.get("scope_value", "")).strip()
            if not policy_id:
                issues.append(f"Row {index}: policy_id must be non-empty.")
            if policy_id in policies:
                issues.append(f"Row {index}: duplicate policy_id '{policy_id}'.")
            if scope_type not in SCOPES:
                issues.append(f"Row {index}: scope_type must be SOURCE_IP, DESTINATION_IP, or SRC_DST_PAIR.")
            elif scope_type in {"SOURCE_IP", "DESTINATION_IP"}:
                if _ip(scope_value) != scope_value:
                    issues.append(f"Row {index}: scope_value must be a literal normalized IP for {scope_type}.")
            else:
                parts = scope_value.split("|")
                if len(parts) != 2 or _ip(parts[0]) != parts[0] or _ip(parts[1]) != parts[1]:
                    issues.append(f"Row {index}: SRC_DST_PAIR must be literal source_ip|destination_ip.")
            policies[policy_id] = row
        return {
            "file": file_path.name, "valid": not issues, "policy_count": len(rows),
            "policies": policies, "errors": issues[:20], "total_errors": len(issues),
        }

    @staticmethod
    def validate_replay(
        file_path: Path,
        expected_records: list[str | int],
        valid_policies: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        rows, issues = _read_csv(file_path, REPLAY_COLUMNS)
        actual_ids = [str(row.get("record_id", "")) for row in rows]
        expected_ids = [str(value) for value in expected_records]
        if actual_ids != expected_ids:
            issues.append("replay.csv must contain every expected record exactly once in original seq order.")
        allow_count = block_count = 0
        for index, row in enumerate(rows):
            action = row.get("action")
            active_id = str(row.get("active_policy_id", "")).strip()
            if action not in ACTIONS:
                issues.append(f"Row {index}: action must be ALLOW or BLOCK.")
            elif action == "ALLOW":
                allow_count += 1
                if active_id != ALLOW_SENTINEL:
                    issues.append(f"Row {index}: ALLOW must use active_policy_id=NONE.")
            else:
                block_count += 1
                if active_id not in valid_policies:
                    issues.append(f"Row {index}: BLOCK must reference a known policy_id.")
        return {
            "file": file_path.name, "valid": not issues, "row_count": len(rows),
            "allow_count": allow_count, "block_count": block_count,
            "errors": issues[:20], "total_errors": len(issues),
        }

    @classmethod
    def validate_submission_bundle(
        cls,
        output_dir: Path,
        expected_records: list[str | int],
        source_frame: Any | None = None,
    ) -> dict[str, Any]:
        """Validate exact headers, IDs, scope provenance, causal windows and tie-breaks."""
        output_dir = Path(output_dir)
        class_result = cls.validate_classification(output_dir / "classification.csv", expected_records)
        policy_result = cls.validate_policy(output_dir / "policies.csv")
        policy_map = policy_result["policies"]
        replay_result = cls.validate_replay(output_dir / "replay.csv", expected_records, policy_map)
        expected_ids = [str(value) for value in expected_records]
        positions = {record_id: index for index, record_id in enumerate(expected_ids)}
        source_rows = None

        if source_frame is not None:
            if len(source_frame) != len(expected_ids) or "record_id" not in source_frame.columns:
                replay_result["valid"] = False
                replay_result["errors"].append("Original hidden input row count or record_id schema does not match submission.")
                replay_result["total_errors"] += 1
            else:
                source_ids = source_frame["record_id"].astype(str).tolist()
                if source_ids != expected_ids:
                    replay_result["valid"] = False
                    replay_result["errors"].append("Original hidden input IDs/order do not match expected organizer records.")
                    replay_result["total_errors"] += 1
                else:
                    source_rows = source_frame.to_dict(orient="records")

        policy_windows: list[dict[str, Any]] = []
        for policy_id, policy in policy_map.items():
            activation_id = str(policy.get("activated_after_record_id", ""))
            expiry_id = str(policy.get("expires_after_record_id", ""))
            if activation_id not in positions or expiry_id not in positions:
                policy_result["valid"] = False
                policy_result["errors"].append(f"Policy {policy_id}: activation and expiry IDs must exist in hidden input.")
                policy_result["total_errors"] += 1
                continue
            start, end = positions[activation_id], positions[expiry_id]
            if start >= end:
                policy_result["valid"] = False
                policy_result["errors"].append(f"Policy {policy_id}: expiry must follow activation.")
                policy_result["total_errors"] += 1
                continue
            scope_type = str(policy.get("scope_type", ""))
            scope_value = str(policy.get("scope_value", "")).strip()
            if source_rows is not None:
                trigger_scope = _scope_for_row(source_rows[start], scope_type)
                if not trigger_scope or trigger_scope != scope_value:
                    policy_result["valid"] = False
                    policy_result["errors"].append(f"Policy {policy_id}: scope_value must exactly match observed endpoints on its activation record.")
                    policy_result["total_errors"] += 1
                    continue
            policy_windows.append({
                "policy_id": policy_id, "scope_type": scope_type, "scope_value": scope_value,
                "start": start, "end": end,
            })

        replay_rows, read_errors = _read_csv(output_dir / "replay.csv", REPLAY_COLUMNS)
        for error in read_errors:
            if error not in replay_result["errors"]:
                replay_result["errors"].append(error)
                replay_result["total_errors"] += 1
        for position, row in enumerate(replay_rows):
            record_id = str(row.get("record_id", ""))
            action = row.get("action")
            active_id = str(row.get("active_policy_id", "")).strip()
            matches: list[str] = []
            for policy in policy_windows:
                if policy["start"] < position <= policy["end"]:
                    if source_rows is None:
                        matches.append(policy["policy_id"])
                    else:
                        observed = _scope_for_row(source_rows[position], policy["scope_type"])
                        if observed and observed == policy["scope_value"]:
                            matches.append(policy["policy_id"])
            expected_policy = min(matches) if matches else ALLOW_SENTINEL
            if action == "ALLOW":
                if active_id != ALLOW_SENTINEL:
                    replay_result["valid"] = False
                    replay_result["errors"].append(f"Record {record_id}: ALLOW must use active_policy_id=NONE.")
                    replay_result["total_errors"] += 1
                if source_rows is not None and matches:
                    replay_result["valid"] = False
                    replay_result["errors"].append(f"Record {record_id}: ALLOW is invalid because active policy {expected_policy} matches.")
                    replay_result["total_errors"] += 1
            elif action == "BLOCK":
                if active_id not in policy_map:
                    continue
                policy = policy_map[active_id]
                activation = str(policy.get("activated_after_record_id", ""))
                expiry = str(policy.get("expires_after_record_id", ""))
                if activation in positions and expiry in positions and not (positions[activation] < position <= positions[expiry]):
                    replay_result["valid"] = False
                    replay_result["errors"].append(f"Record {record_id}: policy {active_id} is outside its activation-exclusive/expiry-inclusive window.")
                    replay_result["total_errors"] += 1
                if source_rows is not None:
                    if not matches:
                        replay_result["valid"] = False
                        replay_result["errors"].append(f"Record {record_id}: BLOCK has no matching active observed-endpoint policy.")
                        replay_result["total_errors"] += 1
                    elif active_id != expected_policy:
                        replay_result["valid"] = False
                        replay_result["errors"].append(f"Record {record_id}: BLOCK must use lexicographically smallest matching policy {expected_policy}.")
                        replay_result["total_errors"] += 1
                elif matches and active_id != expected_policy:
                    replay_result["valid"] = False
                    replay_result["errors"].append(f"Record {record_id}: BLOCK must use lexicographically smallest active policy {expected_policy}.")
                    replay_result["total_errors"] += 1

        all_valid = class_result["valid"] and policy_result["valid"] and replay_result["valid"]
        report = {
            "all_valid": all_valid,
            "status": "LOCAL_VALIDATION_PASSED" if all_valid else "VALIDATION_FAILED",
            "classification": class_result,
            "policies": policy_result,
            "replay": replay_result,
        }
        (output_dir / "validation_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report
